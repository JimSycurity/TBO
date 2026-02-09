using System;
using System.Collections.Generic;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal static class TboDpapiMasterKeyCache
	{
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
					LogDiagnostic(smb, $"TBO: DPAPI master key cache miss ({masterKeyGuid}) for {serverName}.");
					masterKey = null;
					return false;
				}

				LogDiagnostic(smb, $"TBO: DPAPI master key cache hit ({masterKeyGuid}) for {serverName}.");
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

		private static void LogDiagnostic(ISmbProviderInfo smb, string message)
		{
			if (smb is SmbProviderInfo provider)
				provider.LogDiagnostic(message);
		}
	}
}

