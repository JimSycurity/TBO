using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Management.Automation;
using System.Text;
using System.Threading;
using Titanis.Msrpc.Msrrp;
using Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboRegServiceDetailsInfo
	{
		public TboRegServiceDetailsInfo(
			string serverName,
			string keyName,
			string keyPath,
			IReadOnlyList<string>? requiredPrivileges,
			int? launchProtected,
			byte[]? failureActions,
			int? errorControl,
			int? serviceSidType,
			bool? hasServiceCredential,
			string? serviceCredentialKeyPath)
		{
			this.ServerName = serverName;
			this.KeyName = keyName;
			this.KeyPath = keyPath;
			this.RequiredPrivileges = requiredPrivileges;
			this.LaunchProtected = launchProtected;
			this.FailureActions = failureActions;
			this.ErrorControl = errorControl;
			this.ServiceSidType = serviceSidType;
			this.HasServiceCredential = hasServiceCredential;
			this.ServiceCredentialKeyPath = serviceCredentialKeyPath;
		}

		public string ServerName { get; }
		public string KeyName { get; }
		public string KeyPath { get; }
		public IReadOnlyList<string>? RequiredPrivileges { get; }
		public int? LaunchProtected { get; }
		public byte[]? FailureActions { get; }
		public int? ErrorControl { get; }
		public int? ServiceSidType { get; }
		public bool? HasServiceCredential { get; }
		public string? ServiceCredentialKeyPath { get; }
	}

	[Cmdlet(VerbsCommon.Get, "TBORegServiceDetails")]
	[OutputType(typeof(TboRegServiceDetailsInfo))]
	public sealed class GetTBORegServiceDetails : TboRegCmdlet
	{
		private const string DefaultServicesPath = @"HKLM\SYSTEM\CurrentControlSet\Services";
		private const string SecretsPath = @"HKLM\SECURITY\Policy\Secrets";
		private const string ServiceSecretPrefix = "_SC_";

		[Parameter(Position = 1)]
		public string Path { get; set; } = DefaultServicesPath;

		[Parameter(Position = 2, ValueFromPipelineByPropertyName = true)]
		[Alias("ServiceName", "KeyName")]
		public string[]? Name { get; set; }

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

					TryWriteServiceDetails(
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

				if (TryWriteServiceDetails(smb, client, servicesPath, name, cancellationToken, warnOnMissing: true))
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
				if (TryWriteServiceDetails(smb, client, servicesPath, keyName, cancellationToken, warnOnMissing: false))
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
				smb.LogException("Get-TBORegServiceDetails failed to enumerate service keys", ex);
				throw;
			}

			if (servicesInfo.SubkeyCount > 0 && subkeys.Count != servicesInfo.SubkeyCount)
			{
				this.WriteWarning(
					$"Get-TBORegServiceDetails enumerated {subkeys.Count} of {servicesInfo.SubkeyCount} subkeys under {servicesPath.KeyPath}. Some services may be missing.");
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

		private bool TryWriteServiceDetails(
			ISmbProviderInfo smb,
			RemoteRegistryClient client,
			RegistryPathSpec basePath,
			string serviceName,
			CancellationToken cancellationToken,
			bool warnOnMissing)
		{
			try
			{
				WriteServiceDetails(smb, client, basePath, serviceName, cancellationToken);
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
							WriteServiceDetails(smb, session.Client, basePath, serviceName, cancellationToken);
							return true;
						});
				}
				catch (NtstatusException retryEx) when (retryEx.StatusCode == Ntstatus.STATUS_PIPE_BUSY)
				{
					this.WriteWarning($"Get-TBORegServiceDetails failed to read service '{serviceName}': {retryEx.Message}");
				}
				catch (Exception retryEx)
				{
					smb.LogException($"Get-TBORegServiceDetails failed to read service '{serviceName}'", retryEx);
					this.WriteWarning($"Get-TBORegServiceDetails failed to read service '{serviceName}': {retryEx.Message}");
				}
			}
			catch (Win32Exception ex) when (IsMissingKey(ex))
			{
				if (warnOnMissing)
					this.WriteWarning($"Service key not found: {basePath.KeyPath}\\{serviceName}");
			}
			catch (Exception ex)
			{
				smb.LogException($"Get-TBORegServiceDetails failed to read service '{serviceName}'", ex);
				this.WriteWarning($"Get-TBORegServiceDetails failed to read service '{serviceName}': {ex.Message}");
			}

			return false;
		}

		private void WriteServiceDetails(
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

			var requiredPrivileges = TryGetStringArray(values, "RequiredPrivileges");
			var launchProtected = TryGetInt(values, "LaunchProtected");
			var failureActions = TryGetBytes(values, "FailureActions");
			var errorControl = TryGetInt(values, "ErrorControl");
			var serviceSidType = TryGetInt(values, "ServiceSidType");

			bool? hasServiceCredential = TryGetServiceCredential(
				smb,
				client,
				serviceName,
				cancellationToken,
				out var serviceCredentialKeyPath);

			this.WriteObject(new TboRegServiceDetailsInfo(
				this.ServerName,
				serviceName,
				serviceSpec.KeyPath,
				requiredPrivileges,
				launchProtected,
				failureActions,
				errorControl,
				serviceSidType,
				hasServiceCredential,
				serviceCredentialKeyPath));
		}

		private bool? TryGetServiceCredential(
			ISmbProviderInfo smb,
			RemoteRegistryClient client,
			string serviceName,
			CancellationToken cancellationToken,
			out string? secretKeyPath)
		{
			secretKeyPath = null;
			var rootName = RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine);
			var secretSubkey = CombineSubkeyPath(RegistryPathParser.Parse(SecretsPath, nameof(SecretsPath)).SubkeyPath, ServiceSecretPrefix + serviceName);
			var secretSpec = new RegistryPathSpec(RegistryRootKey.LocalMachine, rootName, secretSubkey);
			secretKeyPath = secretSpec.KeyPath;

			try
			{
				using var secretKey = OpenRegistryKey(
					client,
					secretSpec,
					RegistryAccessRights.QueryValue,
					cancellationToken);
				return true;
			}
			catch (Win32Exception ex) when (IsMissingKey(ex))
			{
				return false;
			}
			catch (Exception ex)
			{
				smb.LogException($"Get-TBORegServiceDetails failed to read secret '{secretSpec.KeyPath}'", ex);
				this.WriteWarning($"Get-TBORegServiceDetails failed to read service secret '{secretSpec.KeyPath}': {ex.Message}");
				return null;
			}
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
			foreach (var name in new[] { "RequiredPrivileges", "LaunchProtected", "FailureActions", "ErrorControl", "ServiceSidType" })
			{
				if (values.ContainsKey(name))
					continue;

				try
				{
					var valueInfo = key.GetValue(name, cancellationToken).GetAwaiter().GetResult();
					values[name] = valueInfo;
				}
				catch (Win32Exception ex) when (IsMissingKey(ex))
				{
				}
			}
		}

		private static IReadOnlyList<string>? TryGetStringArray(Dictionary<string, RegistryValueInfo> values, string name)
		{
			if (!values.TryGetValue(name, out var info))
				return null;

			var typed = info.TypedValue;
			if (typed is string[] array)
				return array;
			if (typed is IEnumerable<string> enumerable)
				return enumerable.Where(item => !string.IsNullOrWhiteSpace(item)).ToArray();
			if (typed is string single)
				return SplitMultiString(single);
			if (info.Bytes is { Length: > 0 })
				return DecodeMultiString(info.Bytes);

			return null;
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

		private static byte[]? TryGetBytes(Dictionary<string, RegistryValueInfo> values, string name)
		{
			if (!values.TryGetValue(name, out var info))
				return null;

			if (info.TypedValue is byte[] typedBytes)
				return typedBytes;

			if (info.Bytes is { Length: > 0 })
				return info.Bytes;

			return null;
		}

		private static IReadOnlyList<string> SplitMultiString(string value)
		{
			return value.Split('\0', StringSplitOptions.RemoveEmptyEntries);
		}

		private static IReadOnlyList<string> DecodeMultiString(byte[] data)
		{
			var decoded = Encoding.Unicode.GetString(data);
			return decoded.Split('\0', StringSplitOptions.RemoveEmptyEntries);
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
