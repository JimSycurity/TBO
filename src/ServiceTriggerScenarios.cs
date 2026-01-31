using System;
using System.Collections.Generic;
using System.Text;
using Titanis.Msrpc.Msscmr;
using Titanis.Msrpc.Msrrp;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public enum TboRegServiceTriggerDataType
	{
		Binary = 1,
		String = 2,
		Level = 3,
		KeywordAny = 4,
		KeywordAll = 5
	}

	public sealed class TboRegServiceTriggerWriteValue
	{
		public string Name { get; init; } = string.Empty;
		public RegistryValueType ValueType { get; init; }
		public object? Value { get; init; }
	}

	public sealed class TboRegServiceTriggerDataItemSpec
	{
		public TboRegServiceTriggerDataType DataType { get; init; }
		public byte[] Data { get; init; } = Array.Empty<byte>();
	}

	public static class TboRegServiceTriggerScenarios
	{
		private static readonly Guid DomainJoinGuid = new("1ce20aba-9851-4421-9430-1ddeb766e809");
		private static readonly Guid DomainLeaveGuid = new("ddaf516e-58c2-4866-9574-c3b615d42ea1");
		private static readonly Guid FirewallPortOpenGuid = new("b7569e07-8421-4ee0-ad10-86915afdad09");
		private static readonly Guid FirewallPortCloseGuid = new("a144ed38-8e12-4de4-9d96-e64740b1a524");
		private static readonly Guid MachinePolicyGuid = new("659fcae6-5bdb-4da9-b1ff-ca2a178d46e0");
		private static readonly Guid UserPolicyGuid = new("54fb46c8-f089-464c-b1fd-59d1b62c3b50");
		private static readonly Guid NetworkOnGuid = new("4f27f2de-14e2-430b-a549-7cd48cbc8245");
		private static readonly Guid NetworkOffGuid = new("cc4ba62a-162e-4648-847a-b6bdf993e335");
		private static readonly Guid NamedPipeGuid = new("1f81d131-3fac-4537-9e0c-7e7b0c2f4b55");
		private static readonly Guid RpcInterfaceGuid = new("bc90d167-9470-4139-a9ba-be0bbbf5b74d");

		public static IReadOnlyList<TboRegServiceTriggerWriteValue> StartOnNetworkOn()
			=> BuildSimpleTrigger(ServiceTriggerType.IpAddressAvailability, ServiceTriggerAction.Start, NetworkOnGuid);

		public static IReadOnlyList<TboRegServiceTriggerWriteValue> StopOnNetworkOff()
			=> BuildSimpleTrigger(ServiceTriggerType.IpAddressAvailability, ServiceTriggerAction.Stop, NetworkOffGuid);

		public static IReadOnlyList<TboRegServiceTriggerWriteValue> StartOnDomainJoin()
			=> BuildSimpleTrigger(ServiceTriggerType.DomainJoin, ServiceTriggerAction.Start, DomainJoinGuid);

		public static IReadOnlyList<TboRegServiceTriggerWriteValue> StopOnDomainLeave()
			=> BuildSimpleTrigger(ServiceTriggerType.DomainJoin, ServiceTriggerAction.Stop, DomainLeaveGuid);

		public static IReadOnlyList<TboRegServiceTriggerWriteValue> StartOnMachinePolicy()
			=> BuildSimpleTrigger(ServiceTriggerType.GroupPolicyChange, ServiceTriggerAction.Start, MachinePolicyGuid);

		public static IReadOnlyList<TboRegServiceTriggerWriteValue> StartOnUserPolicy()
			=> BuildSimpleTrigger(ServiceTriggerType.GroupPolicyChange, ServiceTriggerAction.Start, UserPolicyGuid);

		public static IReadOnlyList<TboRegServiceTriggerWriteValue> StartOnFirewallPortOpen(
			string port,
			string protocol,
			string? imagePath = null,
			string? serviceNameOrSid = null)
			=> BuildFirewallPortTrigger(ServiceTriggerAction.Start, FirewallPortOpenGuid, port, protocol, imagePath, serviceNameOrSid);

		public static IReadOnlyList<TboRegServiceTriggerWriteValue> StopOnFirewallPortClose(
			string port,
			string protocol,
			string? imagePath = null,
			string? serviceNameOrSid = null)
			=> BuildFirewallPortTrigger(ServiceTriggerAction.Stop, FirewallPortCloseGuid, port, protocol, imagePath, serviceNameOrSid);

		public static IReadOnlyList<TboRegServiceTriggerWriteValue> StartOnDeviceInterfaceArrival(
			Guid interfaceClassGuid,
			params string[] hardwareIds)
			=> BuildDeviceArrivalTrigger(ServiceTriggerAction.Start, interfaceClassGuid, hardwareIds);

		public static IReadOnlyList<TboRegServiceTriggerWriteValue> StartOnNamedPipe(string pipeName)
			=> BuildNetworkEndpointTrigger(NamedPipeGuid, pipeName);

		public static IReadOnlyList<TboRegServiceTriggerWriteValue> StartOnRpcInterface(Guid interfaceGuid)
			=> BuildNetworkEndpointTrigger(RpcInterfaceGuid, interfaceGuid.ToString());

		public static IReadOnlyList<TboRegServiceTriggerWriteValue> StartOnCustomEtwProvider(
			Guid providerGuid,
			params byte[][] dataItems)
			=> BuildCustomEtwTrigger(ServiceTriggerAction.Start, providerGuid, dataItems);

		public static IReadOnlyList<TboRegServiceTriggerWriteValue> StopOnCustomEtwProvider(
			Guid providerGuid,
			params byte[][] dataItems)
			=> BuildCustomEtwTrigger(ServiceTriggerAction.Stop, providerGuid, dataItems);

		public static IReadOnlyList<TboRegServiceTriggerWriteValue> StartOnCustomEtwProviderStrings(
			Guid providerGuid,
			params string[] dataItems)
			=> BuildCustomEtwTrigger(ServiceTriggerAction.Start, providerGuid, EncodeStringItems(dataItems));

		public static IReadOnlyList<TboRegServiceTriggerWriteValue> StopOnCustomEtwProviderStrings(
			Guid providerGuid,
			params string[] dataItems)
			=> BuildCustomEtwTrigger(ServiceTriggerAction.Stop, providerGuid, EncodeStringItems(dataItems));

		private static IReadOnlyList<TboRegServiceTriggerWriteValue> BuildSimpleTrigger(
			ServiceTriggerType type,
			ServiceTriggerAction action,
			Guid subtype)
		{
			return BuildTriggerValues(type, action, subtype, null);
		}

		private static IReadOnlyList<TboRegServiceTriggerWriteValue> BuildFirewallPortTrigger(
			ServiceTriggerAction action,
			Guid subtype,
			string port,
			string protocol,
			string? imagePath,
			string? serviceNameOrSid)
		{
			if (string.IsNullOrWhiteSpace(port))
				throw new ArgumentException("Port is required.", nameof(port));
			if (string.IsNullOrWhiteSpace(protocol))
				throw new ArgumentException("Protocol is required.", nameof(protocol));

			var parts = new List<string>
			{
				port.Trim(),
				protocol.Trim()
			};

			if (!string.IsNullOrWhiteSpace(imagePath))
				parts.Add(imagePath.Trim());
			if (!string.IsNullOrWhiteSpace(serviceNameOrSid))
				parts.Add(serviceNameOrSid.Trim());

			var dataItems = new List<TboRegServiceTriggerDataItemSpec>
			{
				new()
				{
					DataType = TboRegServiceTriggerDataType.String,
					Data = EncodeMultiString(parts)
				}
			};

			return BuildTriggerValues(ServiceTriggerType.FirewallPortEvent, action, subtype, dataItems);
		}

		private static IReadOnlyList<TboRegServiceTriggerWriteValue> BuildDeviceArrivalTrigger(
			ServiceTriggerAction action,
			Guid subtype,
			string[] hardwareIds)
		{
			var dataItems = new List<TboRegServiceTriggerDataItemSpec>();
			if (hardwareIds != null)
			{
				foreach (var hardwareId in hardwareIds)
				{
					if (string.IsNullOrWhiteSpace(hardwareId))
						continue;

					dataItems.Add(new TboRegServiceTriggerDataItemSpec
					{
						DataType = TboRegServiceTriggerDataType.String,
						Data = EncodeMultiString(hardwareId.Trim())
					});
				}
			}

			return BuildTriggerValues(ServiceTriggerType.InterfaceArrival, action, subtype, dataItems.Count == 0 ? null : dataItems);
		}

		private static IReadOnlyList<TboRegServiceTriggerWriteValue> BuildNetworkEndpointTrigger(Guid subtype, string endpoint)
		{
			if (string.IsNullOrWhiteSpace(endpoint))
				throw new ArgumentException("Endpoint is required.", nameof(endpoint));

			var dataItems = new List<TboRegServiceTriggerDataItemSpec>
			{
				new()
				{
					DataType = TboRegServiceTriggerDataType.String,
					Data = EncodeMultiString(endpoint.Trim())
				}
			};

			return BuildTriggerValues(ServiceTriggerType.NetworkEvent, ServiceTriggerAction.Start, subtype, dataItems);
		}

		private static IReadOnlyList<TboRegServiceTriggerWriteValue> BuildCustomEtwTrigger(
			ServiceTriggerAction action,
			Guid providerGuid,
			IReadOnlyList<TboRegServiceTriggerDataItemSpec>? dataItems)
		{
			return BuildTriggerValues(ServiceTriggerType.Etw, action, providerGuid, dataItems);
		}

		private static IReadOnlyList<TboRegServiceTriggerWriteValue> BuildCustomEtwTrigger(
			ServiceTriggerAction action,
			Guid providerGuid,
			IReadOnlyList<byte[]>? dataItems)
		{
			if (dataItems == null || dataItems.Count == 0)
				return BuildTriggerValues(ServiceTriggerType.Etw, action, providerGuid, null);

			var items = new List<TboRegServiceTriggerDataItemSpec>(dataItems.Count);
			foreach (var data in dataItems)
			{
				items.Add(new TboRegServiceTriggerDataItemSpec
				{
					DataType = TboRegServiceTriggerDataType.Binary,
					Data = data ?? Array.Empty<byte>()
				});
			}

			return BuildTriggerValues(ServiceTriggerType.Etw, action, providerGuid, items);
		}

		private static IReadOnlyList<TboRegServiceTriggerWriteValue> BuildTriggerValues(
			ServiceTriggerType type,
			ServiceTriggerAction action,
			Guid subtype,
			IReadOnlyList<TboRegServiceTriggerDataItemSpec>? dataItems)
		{
			var values = new List<TboRegServiceTriggerWriteValue>
			{
				CreateDword("Type", (uint)type),
				CreateDword("Action", (uint)action),
				CreateBinary("Guid", subtype.ToByteArray())
			};

			if (dataItems == null || dataItems.Count == 0)
				return values;

			for (int i = 0; i < dataItems.Count; i++)
			{
				var item = dataItems[i];
				values.Add(CreateDword($"DataType{i}", (uint)item.DataType));
				values.Add(CreateBinary($"Data{i}", item.Data));
			}

			return values;
		}

		private static TboRegServiceTriggerWriteValue CreateDword(string name, uint value)
		{
			return new TboRegServiceTriggerWriteValue
			{
				Name = name,
				ValueType = RegistryValueType.DwordLE,
				Value = value
			};
		}

		private static TboRegServiceTriggerWriteValue CreateBinary(string name, byte[] data)
		{
			return new TboRegServiceTriggerWriteValue
			{
				Name = name,
				ValueType = RegistryValueType.Binary,
				Value = data ?? Array.Empty<byte>()
			};
		}

		private static IReadOnlyList<byte[]> EncodeStringItems(IReadOnlyList<string>? items)
		{
			if (items == null || items.Count == 0)
				return Array.Empty<byte[]>();

			var results = new List<byte[]>(items.Count);
			foreach (var item in items)
			{
				if (string.IsNullOrWhiteSpace(item))
					continue;
				results.Add(EncodeMultiString(item.Trim()));
			}

			return results;
		}

		private static byte[] EncodeMultiString(IReadOnlyList<string> values)
		{
			if (values == null || values.Count == 0)
				return Encoding.Unicode.GetBytes("\0\0");

			var sb = new StringBuilder();
			foreach (var value in values)
			{
				if (value == null)
					continue;
				sb.Append(value);
				sb.Append('\0');
			}

			sb.Append('\0');
			return Encoding.Unicode.GetBytes(sb.ToString());
		}

		private static byte[] EncodeMultiString(params string[] values)
		{
			return EncodeMultiString((IReadOnlyList<string>)values);
		}
	}
}
