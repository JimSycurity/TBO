using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Management.Automation;
using System.Threading;
using Titanis.Msrpc.Msrrp;
using Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboRegServiceInfo
	{
		public TboRegServiceInfo(
			string serverName,
			string keyName,
			string keyPath,
			string? imagePath,
			string? objectName,
			int? start,
			int? type,
			int? errorControl,
			string? displayName,
			object? securityDescriptor,
			byte[]? securityDescriptorBytes)
		{
			this.ServerName = serverName;
			this.KeyName = keyName;
			this.KeyPath = keyPath;
			this.ImagePath = imagePath;
			this.ObjectName = objectName;
			this.Start = start;
			this.Type = type;
			this.ErrorControl = errorControl;
			this.DisplayName = displayName;
			this.SecurityDescriptor = securityDescriptor;
			this.SecurityDescriptorBytes = securityDescriptorBytes;
		}

		public string ServerName { get; }
		public string KeyName { get; }
		public string KeyPath { get; }
		public string? ImagePath { get; }
		public string? ObjectName { get; }
		public int? Start { get; }
		public int? Type { get; }
		public int? ErrorControl { get; }
		public string? DisplayName { get; }
		public object? SecurityDescriptor { get; }
		public byte[]? SecurityDescriptorBytes { get; }
	}

	[Cmdlet(VerbsCommon.Get, "TBORegServices")]
	[OutputType(typeof(TboRegServiceInfo))]
	public sealed class GetTBORegServices : TboRegCmdlet
	{
		private const string DefaultServicesPath = @"HKLM\SYSTEM\CurrentControlSet\Services";
		private const string SecuritySubkeyName = "Security";
		private const string SecurityValueName = "Security";

		[Parameter(Position = 1)]
		public string Path { get; set; } = DefaultServicesPath;

		[Parameter(Position = 2)]
		[Alias("ServiceName")]
		public string[]? Name { get; set; }

		[Parameter]
		public SwitchParameter AsWindows { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			var basePath = string.IsNullOrWhiteSpace(this.Path) ? DefaultServicesPath : this.Path;
			var parsedPath = ParseRegistryPath(basePath, nameof(this.Path));

			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				using var servicesKey = OpenRegistryKey(
					session.Client,
					parsedPath,
					RegistryAccessRights.EnumerateSubkeys | RegistryAccessRights.QueryValue,
					cancellationToken);

				var keyInfo = servicesKey.QueryInfo(cancellationToken).GetAwaiter().GetResult();
				var requestedNames = FilterNames(this.Name);
				if (requestedNames.Count > 0)
				{
					ProcessRequestedNames(smb, session.Client, parsedPath, servicesKey, keyInfo, requestedNames, cancellationToken);
					return;
				}

				var subkeys = CollectServiceSubkeys(smb, servicesKey, keyInfo, parsedPath, cancellationToken);
				foreach (var subkey in subkeys)
				{
					if (string.IsNullOrWhiteSpace(subkey.KeyName))
						continue;

					TryWriteServiceInfo(
						smb,
						session.Client,
						parsedPath,
						subkey.KeyName,
						cancellationToken,
						warnOnMissing: false);
				}
			});
		}

		private void ProcessRequestedNames(
			ISmbProviderInfo smb,
			RemoteRegistryClient client,
			RegistryPathSpec servicesPath,
			RegistryKey servicesKey,
			RegistryKeyInfo servicesInfo,
			List<string> requestedNames,
			CancellationToken cancellationToken)
		{
			var exactNames = new List<string>();
			var wildcardPatterns = new List<WildcardPattern>();
			var wildcardInputs = new List<string>();
			foreach (var name in requestedNames)
			{
				if (WildcardPattern.ContainsWildcardCharacters(name))
				{
					wildcardPatterns.Add(new WildcardPattern(name, WildcardOptions.IgnoreCase));
					wildcardInputs.Add(name);
				}
				else
					exactNames.Add(name);
			}

			var emitted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			foreach (var name in exactNames)
			{
				if (string.IsNullOrWhiteSpace(name))
					continue;

				if (TryWriteServiceInfo(smb, client, servicesPath, name, cancellationToken, warnOnMissing: true))
					emitted.Add(name);
			}

			if (wildcardPatterns.Count == 0)
				return;

			var subkeys = CollectServiceSubkeys(smb, servicesKey, servicesInfo, servicesPath, cancellationToken);
			var wildcardMatched = false;
			foreach (var subkey in subkeys)
			{
				var keyName = subkey.KeyName;
				if (string.IsNullOrWhiteSpace(keyName) || emitted.Contains(keyName))
					continue;

				if (!MatchesAnyPattern(wildcardPatterns, keyName))
					continue;

				wildcardMatched = true;
				if (TryWriteServiceInfo(smb, client, servicesPath, keyName, cancellationToken, warnOnMissing: false))
					emitted.Add(keyName);
			}

			if (!wildcardMatched)
				this.WriteWarning($"No service keys matched pattern(s): {string.Join(", ", wildcardInputs)}.");
		}

		private List<RegistrySubkeyInfo> CollectServiceSubkeys(
			ISmbProviderInfo smb,
			RegistryKey servicesKey,
			RegistryKeyInfo servicesInfo,
			RegistryPathSpec servicesPath,
			CancellationToken cancellationToken)
		{
			List<RegistrySubkeyInfo> subkeys;
			try
			{
				subkeys = CollectSubkeys(servicesKey, cancellationToken);
			}
			catch (Exception ex)
			{
				smb.LogException("Get-TBORegServices failed to enumerate service keys", ex);
				throw;
			}

			if (servicesInfo.SubkeyCount > 0 && subkeys.Count != servicesInfo.SubkeyCount)
			{
				this.WriteWarning(
					$"Get-TBORegServices enumerated {subkeys.Count} of {servicesInfo.SubkeyCount} subkeys under {servicesPath.KeyPath}. Some services may be missing.");
			}

			return subkeys;
		}

		private static List<string> FilterNames(string[]? names)
		{
			if (names == null || names.Length == 0)
				return new List<string>();

			var filtered = new List<string>(names.Length);
			foreach (var name in names)
			{
				if (!string.IsNullOrWhiteSpace(name))
					filtered.Add(name.Trim());
			}

			return filtered;
		}

		private bool TryWriteServiceInfo(
			ISmbProviderInfo smb,
			RemoteRegistryClient client,
			RegistryPathSpec basePath,
			string serviceName,
			CancellationToken cancellationToken,
			bool warnOnMissing)
		{
			try
			{
				WriteServiceInfo(smb, client, basePath, serviceName, cancellationToken);

				return true;
			}
			catch (NtstatusException ex) when (ex.StatusCode == Ntstatus.STATUS_PIPE_BUSY)
			{
				try
				{
					return ExecuteRegistryOperation(
						smb,
						cancellationToken,
						session =>
						{
							WriteServiceInfo(smb, session.Client, basePath, serviceName, cancellationToken);
							return true;
						});
				}
				catch (NtstatusException retryEx) when (retryEx.StatusCode == Ntstatus.STATUS_PIPE_BUSY)
				{
					this.WriteWarning($"Get-TBORegServices failed to read service '{serviceName}': {retryEx.Message}");
				}
				catch (Exception retryEx)
				{
					smb.LogException($"Get-TBORegServices failed to read service '{serviceName}'", retryEx);
					this.WriteWarning($"Get-TBORegServices failed to read service '{serviceName}': {retryEx.Message}");
				}
			}
			catch (Win32Exception ex) when (IsMissingKey(ex))
			{
				if (warnOnMissing)
					this.WriteWarning($"Service key not found: {basePath.KeyPath}\\{serviceName}");
			}
			catch (Exception ex)
			{
				smb.LogException($"Get-TBORegServices failed to read service '{serviceName}'", ex);
				this.WriteWarning($"Get-TBORegServices failed to read service '{serviceName}': {ex.Message}");
			}

			return false;
		}

		private void WriteServiceInfo(
			ISmbProviderInfo smb,
			RemoteRegistryClient client,
			RegistryPathSpec basePath,
			string serviceName,
			CancellationToken cancellationToken)
		{
			var serviceSpec = new RegistryPathSpec(
				basePath.RootKey,
				basePath.RootName,
				CombineSubkeyPath(basePath.SubkeyPath, serviceName));

			using var serviceKey = OpenRegistryKey(
				client,
				serviceSpec,
				RegistryAccessRights.QueryValue,
				cancellationToken);

			var values = LoadValues(serviceKey, cancellationToken);
			PopulateMissingValues(values, serviceKey, cancellationToken);

			var imagePath = TryGetString(values, "ImagePath");
			var objectName = TryGetString(values, "ObjectName");
			var displayName = TryGetString(values, "DisplayName");
			var start = TryGetInt(values, "Start");
			var type = TryGetInt(values, "Type");
			var errorControl = TryGetInt(values, "ErrorControl");

			byte[]? sdBytes = null;
			object? sd = null;
			TryReadSecurityDescriptor(
				smb,
				client,
				serviceSpec,
				cancellationToken,
				out sdBytes,
				out sd);

			this.WriteObject(new TboRegServiceInfo(
				this.ServerName,
				serviceName,
				serviceSpec.KeyPath,
				imagePath,
				objectName,
				start,
				type,
				errorControl,
				displayName,
				sd,
				sdBytes));
		}

		private static bool MatchesAnyPattern(IReadOnlyList<WildcardPattern> patterns, string value)
		{
			foreach (var pattern in patterns)
			{
				if (pattern.IsMatch(value))
					return true;
			}

			return false;
		}

		private static bool IsMissingKey(Win32Exception ex)
		{
			return ex.NativeErrorCode is (int)Win32ErrorCode.ERROR_FILE_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_PATH_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_BAD_PATHNAME;
		}

		private void TryReadSecurityDescriptor(
			ISmbProviderInfo smb,
			RemoteRegistryClient client,
			RegistryPathSpec serviceSpec,
			CancellationToken cancellationToken,
			out byte[]? sdBytes,
			out object? sd)
		{
			sdBytes = null;
			sd = null;

			try
			{
				var securitySpec = new RegistryPathSpec(
					serviceSpec.RootKey,
					serviceSpec.RootName,
					CombineSubkeyPath(serviceSpec.SubkeyPath, SecuritySubkeyName));

				using var securityKey = OpenRegistryKey(client, securitySpec, RegistryAccessRights.QueryValue, cancellationToken);
				var valueInfo = securityKey.GetValue(SecurityValueName, cancellationToken).GetAwaiter().GetResult();
				sdBytes = valueInfo.Bytes;
				if (sdBytes == null && valueInfo.TypedValue is byte[] typedBytes)
					sdBytes = typedBytes;

				if (sdBytes == null || sdBytes.Length == 0)
					return;

				sd = this.AsWindows.IsPresent
					? (object?)TBOSD.FromRegistryBinaryAsWindows(sdBytes)
					: TBOSD.FromRegistryBinary(sdBytes);
			}
			catch (Win32Exception ex) when (ex.NativeErrorCode is (int)Win32ErrorCode.ERROR_FILE_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_PATH_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_BAD_PATHNAME)
			{
			}
			catch (Exception ex)
			{
				smb.LogException($"Get-TBORegServices failed to read security descriptor for '{serviceSpec.KeyPath}'", ex);
			}
		}

		private static Dictionary<string, RegistryValueInfo> LoadValues(RegistryKey key, CancellationToken cancellationToken)
		{
			try
			{
				return CollectValues(key, includeData: true, cancellationToken)
					.ToDictionary(value => value.Name, StringComparer.OrdinalIgnoreCase);
			}
			catch (NotSupportedException)
			{
				return CollectValues(key, includeData: false, cancellationToken)
					.ToDictionary(value => value.Name, StringComparer.OrdinalIgnoreCase);
			}
		}

		private static void PopulateMissingValues(
			Dictionary<string, RegistryValueInfo> values,
			RegistryKey key,
			CancellationToken cancellationToken)
		{
			foreach (var name in new[] { "ImagePath", "ObjectName", "DisplayName", "Start", "Type", "ErrorControl" })
			{
				if (values.ContainsKey(name))
					continue;

				try
				{
					var valueInfo = key.GetValue(name, cancellationToken).GetAwaiter().GetResult();
					values[name] = valueInfo;
				}
				catch (Win32Exception ex) when (ex.NativeErrorCode is (int)Win32ErrorCode.ERROR_FILE_NOT_FOUND
					or (int)Win32ErrorCode.ERROR_PATH_NOT_FOUND
					or (int)Win32ErrorCode.ERROR_BAD_PATHNAME)
				{
				}
			}
		}

		private static string? TryGetString(Dictionary<string, RegistryValueInfo> values, string name)
		{
			if (!values.TryGetValue(name, out var info))
				return null;

			var typed = info.TypedValue;
			return typed == null ? null : Convert.ToString(typed, CultureInfo.InvariantCulture);
		}

		private static int? TryGetInt(Dictionary<string, RegistryValueInfo> values, string name)
		{
			if (!values.TryGetValue(name, out var info))
				return null;

			var typed = info.TypedValue;
			if (typed == null)
				return null;

			try
			{
				return Convert.ToInt32(typed, CultureInfo.InvariantCulture);
			}
			catch
			{
				return null;
			}
		}

		private static string CombineSubkeyPath(string? basePath, string childName)
		{
			if (string.IsNullOrEmpty(basePath))
				return childName;
			if (string.IsNullOrEmpty(childName))
				return basePath;
			return $"{basePath}\\{childName}";
		}
	}
}
