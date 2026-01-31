using System;
using System.Collections.Generic;
using System.Buffers.Binary;
using Titanis.Msrpc.Msscmr;
using Titanis.Msrpc.Msrrp;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboRegServiceFailureActionWriteValue
	{
		public string Name { get; init; } = string.Empty;
		public RegistryValueType ValueType { get; init; }
		public object? Value { get; init; }
	}

	public sealed class TboRegServiceFailureActionSpec
	{
		public ServiceFailureActionType ActionType { get; init; }
		public uint DelayMs { get; init; }
	}

	public static class TboRegServiceFailureActionScenarios
	{
		public static IReadOnlyList<TboRegServiceFailureActionWriteValue> RunCommandFirst(
			string command,
			uint resetPeriodSeconds = 86400,
			uint runDelayMs = 0,
			IReadOnlyList<TboRegServiceFailureActionSpec>? additionalActions = null,
			bool applyOnNonCrashFailures = false)
		{
			if (string.IsNullOrWhiteSpace(command))
				throw new ArgumentException("Command is required.", nameof(command));

			var actions = new List<TboRegServiceFailureActionSpec>
			{
				new()
				{
					ActionType = ServiceFailureActionType.RunCommand,
					DelayMs = runDelayMs
				}
			};

			if (additionalActions != null && additionalActions.Count > 0)
				actions.AddRange(additionalActions);
			else
				actions.Add(new TboRegServiceFailureActionSpec { ActionType = ServiceFailureActionType.None, DelayMs = 0 });

			return BuildWriteValues(command, resetPeriodSeconds, actions, applyOnNonCrashFailures);
		}

		public static IReadOnlyList<TboRegServiceFailureActionWriteValue> BuildWriteValues(
			string command,
			uint resetPeriodSeconds,
			IReadOnlyList<TboRegServiceFailureActionSpec> actions,
			bool applyOnNonCrashFailures = false)
		{
			if (string.IsNullOrWhiteSpace(command))
				throw new ArgumentException("Command is required.", nameof(command));
			if (actions == null || actions.Count == 0)
				throw new ArgumentException("At least one action is required.", nameof(actions));

			var values = new List<TboRegServiceFailureActionWriteValue>
			{
				new()
				{
					Name = "FailureActions",
					ValueType = RegistryValueType.Binary,
					Value = BuildFailureActionsBinary(resetPeriodSeconds, actions)
				},
				new()
				{
					Name = "FailureCommand",
					ValueType = RegistryValueType.String,
					Value = command
				}
			};

			values.Add(new TboRegServiceFailureActionWriteValue
			{
				Name = "FailureActionsOnNonCrashFailures",
				ValueType = RegistryValueType.DwordLE,
				Value = applyOnNonCrashFailures ? 1u : 0u
			});

			return values;
		}

		private static byte[] BuildFailureActionsBinary(
			uint resetPeriodSeconds,
			IReadOnlyList<TboRegServiceFailureActionSpec> actions)
		{
			const int headerSize = 20;
			const int actionSize = 8;

			int actionCount = actions.Count;
			int actionsOffset = headerSize;
			int totalLength = headerSize + (actionCount * actionSize);
			byte[] buffer = new byte[totalLength];

			BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(0, 4), resetPeriodSeconds);
			BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(4, 4), 0);
			BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(8, 4), 0);
			BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(12, 4), (uint)actionCount);
			BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(16, 4), (uint)actionsOffset);

			for (int i = 0; i < actionCount; i++)
			{
				int offset = actionsOffset + (i * actionSize);
				var action = actions[i];
				BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan(offset, 4), (int)action.ActionType);
				BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(offset + 4, 4), action.DelayMs);
			}

			return buffer;
		}
	}
}
