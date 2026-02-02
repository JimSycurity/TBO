using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Management.Automation;
using System.Text;
using System.Threading;
using Titanis.Msrpc.Msrrp;
using Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboRegTcpIpInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string Protocol { get; init; } = string.Empty;
		public string ParametersKeyPath { get; init; } = string.Empty;
		public string InterfacesKeyPath { get; init; } = string.Empty;
		public string? Domain { get; init; }
		public string? DhcpDomain { get; init; }
		public string[]? SearchList { get; init; }
		public string[]? DhcpSearchList { get; init; }
		public string[]? NameServers { get; init; }
		public string[]? DhcpNameServers { get; init; }
		public bool? RoutingEnabled { get; init; }
		public string[]? PersistentRoutes { get; init; }
		public IReadOnlyList<TboRegTcpIpInterfaceInfo> Interfaces { get; init; } = Array.Empty<TboRegTcpIpInterfaceInfo>();
	}

	public sealed class TboRegTcpIpInterfaceInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string Protocol { get; init; } = string.Empty;
		public string InterfaceId { get; init; } = string.Empty;
		public string? FriendlyName { get; init; }
		public string KeyPath { get; init; } = string.Empty;
		public bool? DhcpEnabled { get; init; }
		public string? DhcpServer { get; init; }
		public string? Domain { get; init; }
		public string? DhcpDomain { get; init; }
		public string[]? SearchList { get; init; }
		public string[]? DhcpSearchList { get; init; }
		public string[]? NameServers { get; init; }
		public string[]? DhcpNameServers { get; init; }
		public string[]? IpAddresses { get; init; }
		public string[]? DhcpIpAddresses { get; init; }
		public string[]? SubnetMasks { get; init; }
		public string[]? DhcpSubnetMasks { get; init; }
		public string[]? DefaultGateways { get; init; }
		public string[]? DhcpDefaultGateways { get; init; }
	}

	[Cmdlet(VerbsCommon.Get, "TBORegTCPIP")]
	[OutputType(typeof(TboRegTcpIpInfo))]
	public sealed class GetTBORegTCPIP : TboRegCmdlet
	{
		private const RegistryKeyOptions BackupOptions = RegistryKeyOptions.BackupRestore;
		private const string TcpipParametersPath = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";
		private const string TcpipInterfacesPath = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
		private const string Tcpip6ParametersPath = @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters";
		private const string Tcpip6InterfacesPath = @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces";
		private const string NetworkConnectionsPath = @"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}";

		[Parameter]
		[ValidateSet("IPv4", "IPv6", "Both")]
		public string Protocol { get; set; } = "Both";

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				foreach (var protocol in ResolveProtocols())
				{
					var interfaceNameMap = BuildInterfaceNameMap(session.Client, smb, cancellationToken);
					var paths = GetProtocolPaths(protocol);
					var parametersSpec = new RegistryPathSpec(
						RegistryRootKey.LocalMachine,
						RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine),
						paths.ParametersPath);
					var interfacesSpec = new RegistryPathSpec(
						RegistryRootKey.LocalMachine,
						RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine),
						paths.InterfacesPath);

					IRegistryKey? parametersKey = null;
					IRegistryKey? interfacesKey = null;
					try
					{
						parametersKey = OpenRegistryKey(session.Client, parametersSpec, RegistryAccessRights.QueryValue, cancellationToken);
						interfacesKey = OpenRegistryKey(session.Client, interfacesSpec, RegistryAccessRights.EnumerateSubkeys | RegistryAccessRights.QueryValue, cancellationToken);
					}
					catch (Win32Exception ex) when (IsMissingKey(ex))
					{
						smb.LogException($"Get-TBORegTCPIP failed to open {protocol} parameters", ex);
						this.WriteWarning($"Get-TBORegTCPIP could not read {protocol} registry data: {ex.Message}");
						parametersKey?.Dispose();
						interfacesKey?.Dispose();
						continue;
					}

					using (parametersKey)
					using (interfacesKey)
					{
						var interfaces = CollectInterfaces(smb, interfacesKey, protocol, interfaceNameMap, cancellationToken);

						this.WriteObject(new TboRegTcpIpInfo
						{
							ServerName = this.ServerName,
							Protocol = protocol,
							ParametersKeyPath = parametersSpec.KeyPath,
							InterfacesKeyPath = interfacesSpec.KeyPath,
							Domain = TryReadString(parametersKey, cancellationToken, "Domain"),
							DhcpDomain = TryReadString(parametersKey, cancellationToken, "DhcpDomain"),
							SearchList = TryReadStringList(parametersKey, cancellationToken, "SearchList"),
							DhcpSearchList = TryReadStringList(parametersKey, cancellationToken, "DhcpSearchList", "Dhcpv6DomainSearchList"),
							NameServers = TryReadStringList(parametersKey, cancellationToken, "NameServer"),
							DhcpNameServers = TryReadStringList(parametersKey, cancellationToken, "DhcpNameServer", "Dhcpv6DNSServers"),
							RoutingEnabled = TryReadBool(parametersKey, cancellationToken, "IPEnableRouter"),
							PersistentRoutes = TryReadStringList(parametersKey, cancellationToken, "PersistentRoutes"),
							Interfaces = interfaces
						});
					}
				}
			});
		}

		private IReadOnlyList<TboRegTcpIpInterfaceInfo> CollectInterfaces(
			ISmbProviderInfo smb,
			IRegistryKey interfacesKey,
			string protocol,
			IReadOnlyDictionary<string, string> interfaceNameMap,
			CancellationToken cancellationToken)
		{
			var results = new List<TboRegTcpIpInterfaceInfo>();
			var subkeys = CollectSubkeys(interfacesKey, cancellationToken);
			foreach (var subkeyInfo in subkeys)
			{
				var name = subkeyInfo.KeyName;
				if (string.IsNullOrWhiteSpace(name))
					continue;

				IRegistryKey? ifaceKey = null;
				try
				{
					ifaceKey = interfacesKey.OpenSubkey(
						name,
						RegistryAccessRights.QueryValue,
						BackupOptions,
						cancellationToken).GetAwaiter().GetResult();
				}
				catch (NtstatusException ex) when (ex.StatusCode == Ntstatus.STATUS_PIPE_BUSY)
				{
					smb.LogException($"Get-TBORegTCPIP failed to read interface {name}", ex);
					this.WriteWarning($"Get-TBORegTCPIP failed to read interface '{name}': {ex.Message}");
					continue;
				}
				catch (Win32Exception ex) when (IsMissingKey(ex) || ex.NativeErrorCode == (int)Win32ErrorCode.ERROR_ACCESS_DENIED)
				{
					continue;
				}

				using (ifaceKey)
				{
					var keyPath = $"{interfacesKey.KeyPath}\\{name}";
					interfaceNameMap.TryGetValue(name, out var friendlyName);
					var dhcpEnabled = TryReadBool(ifaceKey, cancellationToken, "EnableDHCP");
					var ipAddresses = TryReadStringList(ifaceKey, cancellationToken, "IPAddress", "Address");
					var dhcpIpAddresses = TryReadStringList(ifaceKey, cancellationToken, "DhcpIPAddress", "Dhcpv6Address");
					var subnetMasks = TryReadStringList(ifaceKey, cancellationToken, "SubnetMask");
					var dhcpSubnetMasks = TryReadStringList(ifaceKey, cancellationToken, "DhcpSubnetMask");
					var defaultGateways = TryReadStringList(ifaceKey, cancellationToken, "DefaultGateway");
					var dhcpDefaultGateways = TryReadStringList(ifaceKey, cancellationToken, "DhcpDefaultGateway");

					results.Add(new TboRegTcpIpInterfaceInfo
					{
						ServerName = this.ServerName,
						Protocol = protocol,
						InterfaceId = name,
						FriendlyName = friendlyName,
						KeyPath = keyPath,
						DhcpEnabled = dhcpEnabled,
						DhcpServer = TryReadString(ifaceKey, cancellationToken, "DhcpServer"),
						Domain = TryReadString(ifaceKey, cancellationToken, "Domain"),
						DhcpDomain = TryReadString(ifaceKey, cancellationToken, "DhcpDomain"),
						SearchList = TryReadStringList(ifaceKey, cancellationToken, "SearchList"),
						DhcpSearchList = TryReadStringList(ifaceKey, cancellationToken, "DhcpSearchList", "Dhcpv6DomainSearchList"),
						NameServers = TryReadStringList(ifaceKey, cancellationToken, "NameServer"),
						DhcpNameServers = TryReadStringList(ifaceKey, cancellationToken, "DhcpNameServer", "Dhcpv6DNSServers"),
						IpAddresses = ipAddresses,
						DhcpIpAddresses = dhcpIpAddresses,
						SubnetMasks = subnetMasks,
						DhcpSubnetMasks = dhcpSubnetMasks,
						DefaultGateways = defaultGateways,
						DhcpDefaultGateways = dhcpDefaultGateways
					});
				}
			}

			return results;
		}

		private IReadOnlyDictionary<string, string> BuildInterfaceNameMap(
			IRegistryClient client,
			ISmbProviderInfo smb,
			CancellationToken cancellationToken)
		{
			var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
			var spec = new RegistryPathSpec(
				RegistryRootKey.LocalMachine,
				RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine),
				NetworkConnectionsPath);

			IRegistryKey? connectionsKey = null;
			try
			{
				connectionsKey = OpenRegistryKey(client, spec, RegistryAccessRights.EnumerateSubkeys | RegistryAccessRights.QueryValue, cancellationToken);
			}
			catch (Win32Exception ex) when (IsMissingKey(ex))
			{
				return map;
			}

			using (connectionsKey)
			{
				var subkeys = CollectSubkeys(connectionsKey, cancellationToken);
				foreach (var subkeyInfo in subkeys)
				{
					var guid = subkeyInfo.KeyName;
					if (string.IsNullOrWhiteSpace(guid))
						continue;

					IRegistryKey? connectionKey = null;
					try
					{
						connectionKey = connectionsKey.OpenSubkey(
							$"{guid}\\Connection",
							RegistryAccessRights.QueryValue,
							BackupOptions,
							cancellationToken).GetAwaiter().GetResult();
					}
					catch (Win32Exception ex) when (IsMissingKey(ex) || ex.NativeErrorCode == (int)Win32ErrorCode.ERROR_ACCESS_DENIED)
					{
						continue;
					}

					using (connectionKey)
					{
						var name = TryReadString(connectionKey, cancellationToken, "Name");
						if (!string.IsNullOrWhiteSpace(name))
							map[guid] = name;
					}
				}
			}

			return map;
		}

		private static (string ParametersPath, string InterfacesPath) GetProtocolPaths(string protocol)
		{
			return string.Equals(protocol, "IPv6", StringComparison.OrdinalIgnoreCase)
				? (Tcpip6ParametersPath, Tcpip6InterfacesPath)
				: (TcpipParametersPath, TcpipInterfacesPath);
		}

		private IEnumerable<string> ResolveProtocols()
		{
			if (string.Equals(this.Protocol, "IPv4", StringComparison.OrdinalIgnoreCase))
				yield return "IPv4";
			else if (string.Equals(this.Protocol, "IPv6", StringComparison.OrdinalIgnoreCase))
				yield return "IPv6";
			else
			{
				yield return "IPv4";
				yield return "IPv6";
			}
		}

		private static string? TryReadString(IRegistryKey key, CancellationToken cancellationToken, params string[] names)
		{
			foreach (var name in names)
			{
				if (string.IsNullOrWhiteSpace(name))
					continue;

				var value = TryReadValue(key, name, cancellationToken);
				if (value == null)
					continue;

				if (value.TypedValue is string str && !string.IsNullOrWhiteSpace(str))
					return str;

				if (value.Bytes != null && value.Bytes.Length > 0)
				{
					var decoded = DecodeUnicodeString(value.Bytes);
					if (!string.IsNullOrWhiteSpace(decoded))
						return decoded;
				}
			}

			return null;
		}

		private static string[]? TryReadStringList(IRegistryKey key, CancellationToken cancellationToken, params string[] names)
		{
			foreach (var name in names)
			{
				if (string.IsNullOrWhiteSpace(name))
					continue;

				var value = TryReadValue(key, name, cancellationToken);
				if (value == null)
					continue;

				if (value.TypedValue is string[] arr)
					return CleanStringArray(arr);

				if (value.TypedValue is string str)
					return SplitList(str);

				if (value.Bytes != null && value.Bytes.Length > 0)
				{
					if (value.ValueType == RegistryValueType.MultiString)
						return DecodeMultiString(value.Bytes);

					var decoded = DecodeUnicodeString(value.Bytes);
					if (!string.IsNullOrWhiteSpace(decoded))
						return SplitList(decoded);
				}
			}

			return null;
		}

		private static bool? TryReadBool(IRegistryKey key, CancellationToken cancellationToken, params string[] names)
		{
			foreach (var name in names)
			{
				var value = TryReadValue(key, name, cancellationToken);
				if (value == null)
					continue;

				if (value.TypedValue is int intValue)
					return intValue != 0;
				if (value.TypedValue is uint uintValue)
					return uintValue != 0;

				if (value.Bytes != null && value.Bytes.Length >= 4)
					return BitConverter.ToUInt32(value.Bytes, 0) != 0;
			}

			return null;
		}

		private static RegistryValueInfo? TryReadValue(IRegistryKey key, string name, CancellationToken cancellationToken)
		{
			try
			{
				return key.GetValue(name, cancellationToken).GetAwaiter().GetResult();
			}
			catch (Win32Exception ex) when (IsMissingKey(ex))
			{
			}

			return null;
		}

		private static string[]? DecodeMultiString(byte[] bytes)
		{
			try
			{
				var text = Encoding.Unicode.GetString(bytes);
				var parts = text.Split('\0', StringSplitOptions.RemoveEmptyEntries);
				return CleanStringArray(parts);
			}
			catch
			{
				return null;
			}
		}

		private static string? DecodeUnicodeString(byte[] bytes)
		{
			int length = bytes.Length;
			if ((length % 2) != 0)
				return null;

			if (length >= 2 && bytes[^1] == 0 && bytes[^2] == 0)
				length -= 2;

			try
			{
				return Encoding.Unicode.GetString(bytes, 0, length);
			}
			catch
			{
				return null;
			}
		}

		private static string[]? SplitList(string? value)
		{
			if (string.IsNullOrWhiteSpace(value))
				return null;

			var parts = value
				.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)
				.Select(part => part.Trim())
				.Where(part => !string.IsNullOrWhiteSpace(part))
				.ToArray();

			return CleanStringArray(parts);
		}

		private static string[]? CleanStringArray(IEnumerable<string>? values)
		{
			if (values == null)
				return null;

			var cleaned = values
				.Select(value => value?.Trim())
				.Where(value => !string.IsNullOrWhiteSpace(value))
				.ToArray();

			return cleaned.Length == 0 ? null : cleaned;
		}

		private static bool IsMissingKey(Win32Exception ex)
		{
			return ex.NativeErrorCode is (int)Win32ErrorCode.ERROR_FILE_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_PATH_NOT_FOUND
				or (int)Win32ErrorCode.ERROR_BAD_PATHNAME;
		}
	}
}
