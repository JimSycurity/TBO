using System;
using System.Collections.Generic;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal sealed class RegistrySecretCache
	{
		private readonly object _lock = new();
		private byte[]? _bootKey;
		private byte[]? _lsaKey;
		private string? _lsaKeySource;
		private byte[]? _samMasterKey;
		private string? _samAccountDomainSid;
		private Dictionary<Guid, byte[]>? _dpapiMasterKeys;

		internal bool TryGetBootKey(out byte[]? bootKey)
		{
			lock (_lock)
			{
				if (_bootKey == null || _bootKey.Length == 0)
				{
					bootKey = null;
					return false;
				}

				bootKey = (byte[])_bootKey.Clone();
				return true;
			}
		}

		internal void SetBootKey(byte[] bootKey)
		{
			if (bootKey == null || bootKey.Length == 0)
				return;

			lock (_lock)
			{
				_bootKey = (byte[])bootKey.Clone();
			}
		}

		internal bool TryGetLsaKey(out byte[]? lsaKey, out string? source)
		{
			lock (_lock)
			{
				if (_lsaKey == null || _lsaKey.Length == 0)
				{
					lsaKey = null;
					source = null;
					return false;
				}

				lsaKey = (byte[])_lsaKey.Clone();
				source = _lsaKeySource;
				return true;
			}
		}

		internal void SetLsaKey(byte[] lsaKey, string? source)
		{
			if (lsaKey == null || lsaKey.Length == 0)
				return;

			lock (_lock)
			{
				_lsaKey = (byte[])lsaKey.Clone();
				_lsaKeySource = source;
			}
		}

		internal bool TryGetSamMasterKey(out byte[]? masterKey)
		{
			lock (_lock)
			{
				if (_samMasterKey == null || _samMasterKey.Length == 0)
				{
					masterKey = null;
					return false;
				}

				masterKey = (byte[])_samMasterKey.Clone();
				return true;
			}
		}

		internal void SetSamMasterKey(byte[] masterKey)
		{
			if (masterKey == null || masterKey.Length == 0)
				return;

			lock (_lock)
			{
				_samMasterKey = (byte[])masterKey.Clone();
			}
		}

		internal bool TryGetSamAccountDomainSid(out string domainSid)
		{
			lock (_lock)
			{
				if (string.IsNullOrWhiteSpace(_samAccountDomainSid))
				{
					domainSid = string.Empty;
					return false;
				}

				domainSid = _samAccountDomainSid;
				return true;
			}
		}

		internal void SetSamAccountDomainSid(string domainSid)
		{
			if (string.IsNullOrWhiteSpace(domainSid))
				return;

			lock (_lock)
			{
				_samAccountDomainSid = domainSid.Trim();
			}
		}

		internal void Clear()
		{
			lock (_lock)
			{
				_bootKey = null;
				_lsaKey = null;
				_lsaKeySource = null;
				_samMasterKey = null;
				_samAccountDomainSid = null;
				_dpapiMasterKeys = null;
			}
		}

		internal bool TryGetDpapiMasterKey(Guid masterKeyGuid, out byte[]? masterKey)
		{
			lock (_lock)
			{
				if (_dpapiMasterKeys == null || _dpapiMasterKeys.Count == 0)
				{
					masterKey = null;
					return false;
				}

				if (!_dpapiMasterKeys.TryGetValue(masterKeyGuid, out var cached) || cached == null || cached.Length == 0)
				{
					masterKey = null;
					return false;
				}

				masterKey = (byte[])cached.Clone();
				return true;
			}
		}

		internal void SetDpapiMasterKey(Guid masterKeyGuid, byte[] masterKey)
		{
			if (masterKeyGuid == Guid.Empty)
				return;
			if (masterKey == null || masterKey.Length == 0)
				return;

			lock (_lock)
			{
				_dpapiMasterKeys ??= new Dictionary<Guid, byte[]>();
				_dpapiMasterKeys[masterKeyGuid] = (byte[])masterKey.Clone();
			}
		}

		internal void SetDpapiMasterKeys(IEnumerable<KeyValuePair<Guid, byte[]>> masterKeys)
		{
			if (masterKeys == null)
				return;

			lock (_lock)
			{
				_dpapiMasterKeys ??= new Dictionary<Guid, byte[]>();
				foreach (var pair in masterKeys)
				{
					if (pair.Key == Guid.Empty)
						continue;
					if (pair.Value == null || pair.Value.Length == 0)
						continue;
					_dpapiMasterKeys[pair.Key] = (byte[])pair.Value.Clone();
				}
			}
		}
	}
}
