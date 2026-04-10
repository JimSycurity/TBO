using System;
using System.Collections.Generic;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal static class TboDpapiMasterKeyCache
	{
		private static readonly object DiagGateLock = new();
		private static readonly Dictionary<string, DateTime> DiagGate = new(StringComparer.OrdinalIgnoreCase);
		private static readonly TimeSpan DiagRepeatWindow = TimeSpan.FromMinutes(2);
		private const int MaxDiagGateEntries = 4096;

		internal static bool TryGet(
			ISmbProviderInfo smb,
			string serverName,
			Guid masterKeyGuid,
			out byte[]? masterKey)
		{
			masterKey = null;
			if (smb == null)
				return false;
			if (string.IsNullOrWhiteSpace(serverName))
				return false;
			if (masterKeyGuid == Guid.Empty)
				return false;

			try
			{
				if (smb is not IRegistrySecretCacheStore store)
					return false;

				var cache = store.GetOrCreateRegistrySecretCache(serverName);
				if (!cache.TryGetDpapiMasterKey(masterKeyGuid, out masterKey))
				{
					LogDiagnostic(smb, $"miss|{serverName}|{masterKeyGuid}", $"TBO: DPAPI master key cache miss ({masterKeyGuid}) for {serverName}.");
					masterKey = null;
					return false;
				}

				LogDiagnostic(smb, $"hit|{serverName}|{masterKeyGuid}", $"TBO: DPAPI master key cache hit ({masterKeyGuid}) for {serverName}.");
				return masterKey != null && masterKey.Length > 0;
			}
			catch
			{
				masterKey = null;
				return false;
			}
		}

		internal static void TrySet(
			ISmbProviderInfo smb,
			string serverName,
			Guid masterKeyGuid,
			byte[] masterKey)
		{
			if (smb == null)
				return;
			if (string.IsNullOrWhiteSpace(serverName))
				return;
			if (masterKeyGuid == Guid.Empty)
				return;
			if (masterKey == null || masterKey.Length == 0)
				return;

			try
			{
				if (smb is not IRegistrySecretCacheStore store)
					return;

				var cache = store.GetOrCreateRegistrySecretCache(serverName);
				cache.SetDpapiMasterKey(masterKeyGuid, masterKey);
			}
			catch
			{
			}
		}

		internal static void TrySetMany(
			ISmbProviderInfo smb,
			string serverName,
			IEnumerable<KeyValuePair<Guid, byte[]>> masterKeys)
		{
			if (smb == null)
				return;
			if (string.IsNullOrWhiteSpace(serverName))
				return;
			if (masterKeys == null)
				return;

			try
			{
				if (smb is not IRegistrySecretCacheStore store)
					return;

				var cache = store.GetOrCreateRegistrySecretCache(serverName);
				cache.SetDpapiMasterKeys(masterKeys);
			}
			catch
			{
			}
		}

		private static void LogDiagnostic(ISmbProviderInfo smb, string eventKey, string message)
		{
			if (smb is not SmbProviderInfo provider)
				return;
			if (string.IsNullOrWhiteSpace(message))
				return;
			if (string.IsNullOrWhiteSpace(eventKey))
				return;
			if (!ShouldEmitDiagnostic(eventKey))
				return;

			provider.LogDiagnostic(message);
		}

		private static bool ShouldEmitDiagnostic(string eventKey)
		{
			var now = DateTime.UtcNow;
			lock (DiagGateLock)
			{
				if (DiagGate.TryGetValue(eventKey, out var lastLogUtc)
					&& (now - lastLogUtc) < DiagRepeatWindow)
				{
					return false;
				}

				if (DiagGate.Count >= MaxDiagGateEntries)
				{
					var staleCutoff = now - DiagRepeatWindow;
					var staleKeys = new List<string>();
					foreach (var kv in DiagGate)
					{
						if (kv.Value < staleCutoff)
							staleKeys.Add(kv.Key);
					}

					foreach (var key in staleKeys)
						DiagGate.Remove(key);

					if (DiagGate.Count >= MaxDiagGateEntries)
						DiagGate.Clear();
				}

				DiagGate[eventKey] = now;
				return true;
			}
		}
	}
}
