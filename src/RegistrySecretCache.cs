using System;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal sealed class RegistrySecretCache
	{
		private readonly object _lock = new();
		private byte[]? _bootKey;
		private byte[]? _lsaKey;
		private string? _lsaKeySource;
		private byte[]? _samMasterKey;

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

		internal void Clear()
		{
			lock (_lock)
			{
				_bootKey = null;
				_lsaKey = null;
				_lsaKeySource = null;
				_samMasterKey = null;
			}
		}
	}
}
