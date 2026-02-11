using System;
using System.Collections.Generic;
using Titanis.Msrpc.Msrrp;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboRegServiceCreateWriteValue
	{
		public string Name { get; init; } = string.Empty;
		public RegistryValueType ValueType { get; init; }
		public object? Value { get; init; }
	}

	public static class TboRegServiceCreateScenarios
	{
		private const uint ServiceAutoStart = 2;
		private const uint ServiceWin32OwnProcess = 0x00000010;
		private const uint ServiceErrorNormal = 1;

		public static IReadOnlyList<TboRegServiceCreateWriteValue> AutoStartOwnProcess(
			string imagePath,
			string? displayName = null,
			string? description = null,
			string objectName = "LocalSystem")
		{
			return BuildWriteValues(
				imagePath,
				start: ServiceAutoStart,
				type: ServiceWin32OwnProcess,
				errorControl: ServiceErrorNormal,
				objectName: objectName,
				displayName: displayName,
				description: description);
		}

		public static IReadOnlyList<TboRegServiceCreateWriteValue> BuildWriteValues(
			string imagePath,
			uint start,
			uint type,
			uint errorControl,
			string objectName = "LocalSystem",
			string? displayName = null,
			string? description = null)
		{
			if (string.IsNullOrWhiteSpace(imagePath))
				throw new ArgumentException("ImagePath is required.", nameof(imagePath));
			if (string.IsNullOrWhiteSpace(objectName))
				throw new ArgumentException("ObjectName is required.", nameof(objectName));

			var values = new List<TboRegServiceCreateWriteValue>
			{
				CreateDword("Start", start),
				CreateDword("Type", type),
				CreateDword("ErrorControl", errorControl),
				CreateString("ObjectName", objectName.Trim()),
				CreateString("ImagePath", imagePath.Trim(), expand: true)
			};

			if (!string.IsNullOrWhiteSpace(displayName))
				values.Add(CreateString("DisplayName", displayName.Trim()));
			if (!string.IsNullOrWhiteSpace(description))
				values.Add(CreateString("Description", description.Trim()));

			return values;
		}

		private static TboRegServiceCreateWriteValue CreateDword(string name, uint value)
		{
			return new TboRegServiceCreateWriteValue
			{
				Name = name,
				ValueType = RegistryValueType.DwordLE,
				Value = value
			};
		}

		private static TboRegServiceCreateWriteValue CreateString(string name, string value, bool expand = false)
		{
			return new TboRegServiceCreateWriteValue
			{
				Name = name,
				ValueType = expand ? RegistryValueType.ExpandString : RegistryValueType.String,
				Value = value
			};
		}
	}
}
