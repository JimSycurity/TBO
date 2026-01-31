using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Management.Automation;
using System.Text.RegularExpressions;
using System.Threading;
using Titanis.Msrpc.Msrrp;
using Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboRegSecretLocationInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string Hive { get; init; } = string.Empty;
		public string KeyPath { get; init; } = string.Empty;
		public string? UserSid { get; init; }
		public string Category { get; init; } = string.Empty;
		public IReadOnlyList<string>? ValueNames { get; init; }
		public string? Notes { get; init; }
		public string? HandledBy { get; init; }
		public bool Exists { get; init; }
	}

	[Cmdlet(VerbsCommon.Get, "TBORegSecretLocations")]
	[OutputType(typeof(TboRegSecretLocationInfo))]
	public sealed class GetTBORegSecretLocations : TboRegCmdlet
	{
		private const string WinlogonPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
		private const string LsaSecretsPath = @"SECURITY\Policy\Secrets";
		private const string CachedCredsPath = @"SECURITY\Cache";
		private const string SnmpPath = @"SYSTEM\CurrentControlSet\Services\SNMP";
		private const string RealVncPath = @"SOFTWARE\RealVNC\WinVNC4";

		private const string PuttySessionsPath = @"Software\SimonTatham\PuTTY\Sessions";
		private const string WinVncLegacyPath = @"Software\ORL\WinVNC3";
		private const string WinVncLegacyPasswordValue = "Password";
		private const string RdpServersPath = @"Software\Microsoft\Terminal Server Client\Servers";
		private const string RdpDefaultPath = @"Software\Microsoft\Terminal Server Client\Default";

		private static readonly string[] AutologonValueNames =
		{
			"AutoAdminLogon",
			"DefaultUserName",
			"DefaultDomainName",
			"DefaultPassword"
		};

		private sealed class SecretLocationDefinition
		{
			public RegistryRootKey RootKey { get; init; }
			public string SubkeyPath { get; init; } = string.Empty;
			public string Category { get; init; } = string.Empty;
			public string? Notes { get; init; }
			public string? HandledBy { get; init; }
			public IReadOnlyList<string>? ValueNames { get; init; }
			public bool RequiresUserSid { get; init; }
		}

		[Parameter]
		public SwitchParameter IncludeMissing { get; set; }

		[Parameter]
		public SwitchParameter IncludeSystemHives { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			var definitions = BuildDefinitions();

			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				foreach (var definition in definitions.Where(def => def.RootKey != RegistryRootKey.Users))
				{
					ProcessDefinition(session.Client, definition, null, cancellationToken);
				}

				var userSids = CollectUserHives(session.Client, cancellationToken);
				foreach (var sid in userSids)
				{
					foreach (var definition in definitions.Where(def => def.RootKey == RegistryRootKey.Users))
					{
						ProcessDefinition(session.Client, definition, sid, cancellationToken);
					}
				}
			});
		}

		private IReadOnlyList<SecretLocationDefinition> BuildDefinitions()
		{
			return new List<SecretLocationDefinition>
			{
				new()
				{
					RootKey = RegistryRootKey.LocalMachine,
					SubkeyPath = WinlogonPath,
					Category = "AutoLogon",
					ValueNames = AutologonValueNames,
					Notes = "Autologon configuration values.",
					HandledBy = "Get-TBORegAutoLogon"
				},
				new()
				{
					RootKey = RegistryRootKey.LocalMachine,
					SubkeyPath = LsaSecretsPath,
					Category = "LsaSecrets",
					Notes = "LSA secrets (SECURITY\\Policy\\Secrets).",
					HandledBy = "Get-TBORegLsaSecrets"
				},
				new()
				{
					RootKey = RegistryRootKey.LocalMachine,
					SubkeyPath = CachedCredsPath,
					Category = "CachedCredentials",
					Notes = "Cached domain credentials (SECURITY\\Cache).",
					HandledBy = "Get-TBORegCachedCredentials"
				},
				new()
				{
					RootKey = RegistryRootKey.LocalMachine,
					SubkeyPath = RealVncPath,
					Category = "Vnc",
					Notes = "RealVNC service configuration (WinVNC4)."
				},
				new()
				{
					RootKey = RegistryRootKey.LocalMachine,
					SubkeyPath = SnmpPath,
					Category = "Snmp",
					Notes = "SNMP service configuration (community strings in Parameters subkeys)."
				},
				new()
				{
					RootKey = RegistryRootKey.Users,
					SubkeyPath = PuttySessionsPath,
					Category = "PuTTY",
					RequiresUserSid = true,
					Notes = "PuTTY saved sessions."
				},
				new()
				{
					RootKey = RegistryRootKey.Users,
					SubkeyPath = WinVncLegacyPath,
					Category = "Vnc",
					RequiresUserSid = true,
					ValueNames = new[] { WinVncLegacyPasswordValue },
					Notes = "Legacy WinVNC3 password value."
				},
				new()
				{
					RootKey = RegistryRootKey.Users,
					SubkeyPath = RdpServersPath,
					Category = "Rdp",
					RequiresUserSid = true,
					Notes = "RDP saved server entries."
				},
				new()
				{
					RootKey = RegistryRootKey.Users,
					SubkeyPath = RdpDefaultPath,
					Category = "Rdp",
					RequiresUserSid = true,
					Notes = "RDP default settings."
				}
			};
		}

		private void ProcessDefinition(
			RemoteRegistryClient client,
			SecretLocationDefinition definition,
			string? userSid,
			CancellationToken cancellationToken)
		{
			if (definition.RequiresUserSid && string.IsNullOrWhiteSpace(userSid))
				return;

			var subkeyPath = definition.RequiresUserSid
				? CombineSubkeyPath(userSid, definition.SubkeyPath) ?? definition.SubkeyPath
				: definition.SubkeyPath;

			var spec = new RegistryPathSpec(
				definition.RootKey,
				RemoteRegistryClient.GetRootName(definition.RootKey),
				subkeyPath);

			bool exists = TryKeyExists(client, spec, cancellationToken);
			if (!exists && !this.IncludeMissing.IsPresent)
				return;

			var hiveLabel = definition.RootKey == RegistryRootKey.Users ? "HKU" : "HKLM";
			this.WriteObject(new TboRegSecretLocationInfo
			{
				ServerName = this.ServerName,
				Hive = hiveLabel,
				KeyPath = spec.KeyPath,
				UserSid = definition.RequiresUserSid ? userSid : null,
				Category = definition.Category,
				ValueNames = definition.ValueNames,
				Notes = definition.Notes,
				HandledBy = definition.HandledBy,
				Exists = exists
			});
		}

		private List<string> CollectUserHives(RemoteRegistryClient client, CancellationToken cancellationToken)
		{
			var userSpec = new RegistryPathSpec(
				RegistryRootKey.Users,
				RemoteRegistryClient.GetRootName(RegistryRootKey.Users),
				null);

			using var usersKey = OpenRegistryKey(client, userSpec, RegistryAccessRights.EnumerateSubkeys, cancellationToken);
			var subkeys = CollectSubkeys(usersKey, cancellationToken);
			var hives = new List<string>();
			foreach (var subkey in subkeys)
			{
				var name = subkey.KeyName;
				if (string.IsNullOrWhiteSpace(name))
					continue;

				if (IsUserSid(name) || this.IncludeSystemHives.IsPresent)
					hives.Add(name);
			}

			return hives;
		}

		private static bool IsUserSid(string name)
		{
			if (name.Equals(".DEFAULT", StringComparison.OrdinalIgnoreCase))
				return false;

			return UserSidPattern.IsMatch(name);
		}

		private static bool TryKeyExists(RemoteRegistryClient client, RegistryPathSpec spec, CancellationToken cancellationToken)
		{
			try
			{
				using var key = client.OpenRootKey(spec.RootKey, RegistryAccessRights.EnumerateSubkeys, cancellationToken).GetAwaiter().GetResult();
				if (spec.IsRoot)
					return true;

				using var subkey = key.OpenSubkey(spec.SubkeyPath ?? string.Empty, RegistryAccessRights.QueryValue, RegistryKeyOptions.BackupRestore, cancellationToken).GetAwaiter().GetResult();
				return subkey != null;
			}
			catch (Win32Exception ex) when (IsMissingKey(ex))
			{
				return false;
			}
		}

		private static bool IsMissingKey(Win32Exception ex)
		{
			return ex.NativeErrorCode is (int)Win32ErrorCode.ERROR_FILE_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_PATH_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_BAD_PATHNAME;
		}

		private static string? CombineSubkeyPath(string? basePath, string childName)
		{
			if (string.IsNullOrEmpty(basePath))
				return childName;
			if (string.IsNullOrEmpty(childName))
				return basePath;
			return $"{basePath}\\{childName}";
		}

		private static readonly Regex UserSidPattern = new(
			@"^S-1-(5-21|12-1)-\d+(-\d+){2,}$",
			RegexOptions.Compiled | RegexOptions.IgnoreCase);
	}
}
