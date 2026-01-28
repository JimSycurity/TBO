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

		[Parameter]
		public SwitchParameter AsWindows { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			var basePath = string.IsNullOrWhiteSpace(this.Path) ? DefaultServicesPath : this.Path;
			var parsedPath = ParseRegistryPath(basePath, nameof(this.Path));

			using var session = OpenRegistrySession(smb, cancellationToken);
			using var servicesKey = OpenRegistryKey(
				session.Client,
				parsedPath,
				RegistryAccessRights.EnumerateSubkeys | RegistryAccessRights.QueryValue,
				cancellationToken);

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

			foreach (var subkey in subkeys)
			{
				if (string.IsNullOrEmpty(subkey.KeyName))
					continue;

				try
				{
					var serviceSpec = new RegistryPathSpec(
						parsedPath.RootKey,
						parsedPath.RootName,
						CombineSubkeyPath(parsedPath.SubkeyPath, subkey.KeyName));

					using var serviceKey = OpenRegistryKey(
						session.Client,
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
						session.Client,
						serviceSpec,
						cancellationToken,
						out sdBytes,
						out sd);

					var keyPath = serviceSpec.KeyPath;
					this.WriteObject(new TboRegServiceInfo(
						this.ServerName,
						subkey.KeyName,
						keyPath,
						imagePath,
						objectName,
						start,
						type,
						errorControl,
						displayName,
						sd,
						sdBytes));
				}
				catch (Exception ex)
				{
					smb.LogException($"Get-TBORegServices failed to read service '{subkey.KeyName}'", ex);
				}
			}
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
