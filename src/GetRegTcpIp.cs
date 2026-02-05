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

		private sealed class TcpIpParametersSnapshot
		{
			public string? Domain { get; init; }
			public string? DhcpDomain { get; init; }
			public string[]? SearchList { get; init; }
			public string[]? DhcpSearchList { get; init; }
			public string[]? NameServers { get; init; }
			public string[]? DhcpNameServers { get; init; }
			public bool? RoutingEnabled { get; init; }
			public string[]? PersistentRoutes { get; init; }
		}

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			var interfaceNameMap = BuildInterfaceNameMap(smb, cancellationToken);
			foreach (var protocol in ResolveProtocols())
			{
				if (!TryBuildProtocolInfo(smb, protocol, interfaceNameMap, cancellationToken, out var info))
					continue;

				this.WriteObject(info);
			}
		}

		private bool TryBuildProtocolInfo(
			ISmbProviderInfo smb,
			string protocol,
			IReadOnlyDictionary<string, string> interfaceNameMap,
			CancellationToken cancellationToken,
			out TboRegTcpIpInfo info)
		{
			info = null!;
			var paths = GetProtocolPaths(protocol);
			var parametersSpec = new RegistryPathSpec(
				RegistryRootKey.LocalMachine,
				RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine),
				paths.ParametersPath);
			var interfacesSpec = new RegistryPathSpec(
				RegistryRootKey.LocalMachine,
				RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine),
				paths.InterfacesPath);

			var parameters = TryReadProtocolParameters(smb, protocol, parametersSpec, cancellationToken);
			if (parameters == null)
				return false;

			var interfaceIds = TryReadInterfaceIds(smb, protocol, interfacesSpec, cancellationToken);
			if (interfaceIds == null)
				return false;

			var interfaces = new List<TboRegTcpIpInterfaceInfo>();
			foreach (var interfaceId in interfaceIds)
			{
				var interfaceInfo = TryReadInterfaceInfo(
					smb,
					protocol,
					interfacesSpec,
					interfaceId,
					interfaceNameMap,
					cancellationToken);
				if (interfaceInfo != null)
					interfaces.Add(interfaceInfo);
			}

			info = new TboRegTcpIpInfo
			{
				ServerName = this.ServerName,
				Protocol = protocol,
				ParametersKeyPath = parametersSpec.KeyPath,
				InterfacesKeyPath = interfacesSpec.KeyPath,
				Domain = parameters.Domain,
				DhcpDomain = parameters.DhcpDomain,
				SearchList = parameters.SearchList,
				DhcpSearchList = parameters.DhcpSearchList,
				NameServers = parameters.NameServers,
				DhcpNameServers = parameters.DhcpNameServers,
				RoutingEnabled = parameters.RoutingEnabled,
				PersistentRoutes = parameters.PersistentRoutes,
				Interfaces = interfaces
			};
			return true;
		}

		private TcpIpParametersSnapshot? TryReadProtocolParameters(
			ISmbProviderInfo smb,
			string protocol,
			RegistryPathSpec parametersSpec,
			CancellationToken cancellationToken)
		{
			try
			{
				return ExecuteRegistryOperation(smb, cancellationToken, session =>
				{
					using var parametersKey = OpenRegistryKey(session.Client, parametersSpec, RegistryAccessRights.QueryValue, cancellationToken);
					return new TcpIpParametersSnapshot
					{
						Domain = TryReadString(parametersKey, cancellationToken, "Domain"),
						DhcpDomain = TryReadString(parametersKey, cancellationToken, "DhcpDomain"),
						SearchList = TryReadStringList(parametersKey, cancellationToken, "SearchList"),
						DhcpSearchList = TryReadStringList(parametersKey, cancellationToken, "DhcpSearchList", "Dhcpv6DomainSearchList"),
						NameServers = TryReadStringList(parametersKey, cancellationToken, "NameServer"),
						DhcpNameServers = TryReadStringList(parametersKey, cancellationToken, "DhcpNameServer", "Dhcpv6DNSServers"),
						RoutingEnabled = TryReadBool(parametersKey, cancellationToken, "IPEnableRouter"),
						PersistentRoutes = TryReadStringList(parametersKey, cancellationToken, "PersistentRoutes")
					};
				});
			}
			catch (Win32Exception ex) when (IsMissingKey(ex))
			{
				smb.LogException($"Get-TBORegTCPIP failed to open {protocol} parameters", ex);
				this.WriteWarning($"Get-TBORegTCPIP could not read {protocol} registry parameters: {ex.Message}");
				return null;
			}
			catch (NtstatusException ex) when (ex.StatusCode == Ntstatus.STATUS_PIPE_BUSY)
			{
				smb.LogException($"Get-TBORegTCPIP failed to read {protocol} parameters", ex);
				this.WriteWarning($"Get-TBORegTCPIP could not read {protocol} registry parameters: {ex.Message}");
				return null;
			}
		}

		private List<string>? TryReadInterfaceIds(
			ISmbProviderInfo smb,
			string protocol,
			RegistryPathSpec interfacesSpec,
			CancellationToken cancellationToken)
		{
			try
			{
				return ExecuteRegistryOperation(smb, cancellationToken, session =>
				{
					using var interfacesKey = OpenRegistryKey(
						session.Client,
						interfacesSpec,
						RegistryAccessRights.EnumerateSubkeys,
						cancellationToken);
					var subkeys = CollectSubkeys(interfacesKey, cancellationToken);
					return subkeys
						.Select(subkeyInfo => subkeyInfo.KeyName)
						.Where(name => !string.IsNullOrWhiteSpace(name))
						.ToList();
				});
			}
			catch (Win32Exception ex) when (IsMissingKey(ex))
			{
				smb.LogException($"Get-TBORegTCPIP failed to open {protocol} interfaces", ex);
				this.WriteWarning($"Get-TBORegTCPIP could not read {protocol} interface list: {ex.Message}");
				return null;
			}
			catch (NtstatusException ex) when (ex.StatusCode == Ntstatus.STATUS_PIPE_BUSY)
			{
				smb.LogException($"Get-TBORegTCPIP failed to enumerate {protocol} interfaces", ex);
				this.WriteWarning($"Get-TBORegTCPIP could not read {protocol} interface list: {ex.Message}");
				return null;
			}
		}

		private TboRegTcpIpInterfaceInfo? TryReadInterfaceInfo(
			ISmbProviderInfo smb,
			string protocol,
			RegistryPathSpec interfacesSpec,
			string interfaceId,
			IReadOnlyDictionary<string, string> interfaceNameMap,
			CancellationToken cancellationToken)
		{
			try
			{
				return ExecuteRegistryOperation(smb, cancellationToken, session =>
				{
					using var interfacesKey = OpenRegistryKey(
						session.Client,
						interfacesSpec,
						RegistryAccessRights.QueryValue,
						RegistryAccessRights.EnumerateSubkeys,
						cancellationToken);
					using var ifaceKey = interfacesKey.OpenSubkey(
						interfaceId,
						RegistryAccessRights.QueryValue,
						BackupOptions,
						cancellationToken).GetAwaiter().GetResult();

					var keyPath = $"{interfacesSpec.KeyPath}\\{interfaceId}";
					interfaceNameMap.TryGetValue(interfaceId, out var friendlyName);
					var dhcpEnabled = TryReadBool(ifaceKey, cancellationToken, "EnableDHCP");
					var ipAddresses = TryReadStringList(ifaceKey, cancellationToken, "IPAddress", "Address");
					var dhcpIpAddresses = TryReadStringList(ifaceKey, cancellationToken, "DhcpIPAddress", "Dhcpv6Address");
					var subnetMasks = TryReadStringList(ifaceKey, cancellationToken, "SubnetMask");
					var dhcpSubnetMasks = TryReadStringList(ifaceKey, cancellationToken, "DhcpSubnetMask");
					var defaultGateways = TryReadStringList(ifaceKey, cancellationToken, "DefaultGateway");
					var dhcpDefaultGateways = TryReadStringList(ifaceKey, cancellationToken, "DhcpDefaultGateway");

					return new TboRegTcpIpInterfaceInfo
					{
						ServerName = this.ServerName,
						Protocol = protocol,
						InterfaceId = interfaceId,
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
					};
				});
			}
			catch (NtstatusException ex) when (ex.StatusCode == Ntstatus.STATUS_PIPE_BUSY)
			{
				smb.LogException($"Get-TBORegTCPIP failed to read interface {interfaceId}", ex);
				this.WriteWarning($"Get-TBORegTCPIP failed to read interface '{interfaceId}': {ex.Message}");
				return null;
			}
			catch (Win32Exception ex) when (IsMissingKey(ex) || ex.NativeErrorCode == (int)Win32ErrorCode.ERROR_ACCESS_DENIED)
			{
				return null;
			}
			catch (Exception ex)
			{
				smb.LogException($"Get-TBORegTCPIP failed to read interface {interfaceId}", ex);
				this.WriteWarning($"Get-TBORegTCPIP failed to read interface '{interfaceId}': {ex.Message}");
				return null;
			}
		}

		private IReadOnlyDictionary<string, string> BuildInterfaceNameMap(
			ISmbProviderInfo smb,
			CancellationToken cancellationToken)
		{
			var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
			var interfaceIds = TryReadNetworkInterfaceIds(smb, cancellationToken);
			if (interfaceIds.Count == 0)
				return map;

			foreach (var interfaceId in interfaceIds)
			{
				var friendlyName = TryReadNetworkInterfaceName(smb, interfaceId, cancellationToken);
				if (!string.IsNullOrWhiteSpace(friendlyName))
					map[interfaceId] = friendlyName;
			}

			return map;
		}

		private List<string> TryReadNetworkInterfaceIds(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			var spec = new RegistryPathSpec(
				RegistryRootKey.LocalMachine,
				RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine),
				NetworkConnectionsPath);
			try
			{
				return ExecuteRegistryOperation(smb, cancellationToken, session =>
				{
					using var connectionsKey = OpenRegistryKey(
						session.Client,
						spec,
						RegistryAccessRights.EnumerateSubkeys | RegistryAccessRights.QueryValue,
						cancellationToken);
					var subkeys = CollectSubkeys(connectionsKey, cancellationToken);
					return subkeys
						.Select(subkeyInfo => subkeyInfo.KeyName)
						.Where(name => !string.IsNullOrWhiteSpace(name))
						.ToList();
				});
			}
			catch (Win32Exception ex) when (IsMissingKey(ex))
			{
				return new List<string>();
			}
			catch (Exception ex)
			{
				smb.LogException("Get-TBORegTCPIP failed to enumerate network connections", ex);
				this.WriteWarning($"Get-TBORegTCPIP failed to read interface names: {ex.Message}");
				return new List<string>();
			}
		}

		private string? TryReadNetworkInterfaceName(
			ISmbProviderInfo smb,
			string interfaceId,
			CancellationToken cancellationToken)
		{
			var spec = new RegistryPathSpec(
				RegistryRootKey.LocalMachine,
				RemoteRegistryClient.GetRootName(RegistryRootKey.LocalMachine),
				NetworkConnectionsPath);
			try
			{
				return ExecuteRegistryOperation(smb, cancellationToken, session =>
				{
					using var connectionsKey = OpenRegistryKey(
						session.Client,
						spec,
						RegistryAccessRights.EnumerateSubkeys | RegistryAccessRights.QueryValue,
						cancellationToken);
					using var connectionKey = connectionsKey.OpenSubkey(
						$"{interfaceId}\\Connection",
						RegistryAccessRights.QueryValue,
						BackupOptions,
						cancellationToken).GetAwaiter().GetResult();
					return TryReadString(connectionKey, cancellationToken, "Name");
				});
			}
			catch (Win32Exception ex) when (IsMissingKey(ex) || ex.NativeErrorCode == (int)Win32ErrorCode.ERROR_ACCESS_DENIED)
			{
				return null;
			}
			catch (NtstatusException ex) when (ex.StatusCode == Ntstatus.STATUS_PIPE_BUSY)
			{
				smb.LogException($"Get-TBORegTCPIP failed to read interface name for {interfaceId}", ex);
				this.WriteWarning($"Get-TBORegTCPIP failed to read interface '{interfaceId}' name: {ex.Message}");
				return null;
			}
			catch (Exception ex)
			{
				smb.LogException($"Get-TBORegTCPIP failed to read interface name for {interfaceId}", ex);
				this.WriteWarning($"Get-TBORegTCPIP failed to read interface '{interfaceId}' name: {ex.Message}");
				return null;
			}
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
