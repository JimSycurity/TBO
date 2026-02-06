using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal sealed class DpapiMasterKeyCredHistBlock
	{
		public uint Version { get; init; }
		public Guid Guid { get; init; }

		public static DpapiMasterKeyCredHistBlock? Parse(byte[] raw)
		{
			if (raw == null || raw.Length < 20)
				return null;

			var version = BitConverter.ToUInt32(raw, 0);
			var guidBytes = raw.AsSpan(4, 16).ToArray();
			var guid = new Guid(guidBytes);

			return new DpapiMasterKeyCredHistBlock
			{
				Version = version,
				Guid = guid
			};
		}
	}

	internal sealed class DpapiCredHistFile
	{
		public IReadOnlyList<DpapiCredHistEntry> Entries { get; init; } = Array.Empty<DpapiCredHistEntry>();
		public IReadOnlyDictionary<Guid, DpapiCredHistEntry> EntriesByGuid { get; init; } = new Dictionary<Guid, DpapiCredHistEntry>();
		public uint FooterMagic { get; init; }
		public Guid? CurrentGuid { get; init; }

		public static DpapiCredHistFile Parse(byte[] raw)
		{
			if (raw == null || raw.Length == 0)
				throw new ArgumentException("CREDHIST data must be provided.", nameof(raw));

			var entries = new List<DpapiCredHistEntry>();
			var byGuid = new Dictionary<Guid, DpapiCredHistEntry>();

			var offset = 0;
			while (true)
			{
				if (offset + 4 > raw.Length)
					throw new InvalidDataException("CREDHIST entry length exceeds available data.");

				var len = BitConverter.ToUInt32(raw, offset);
				offset += 4;
				if (len == 0)
					break;
				if (len < 4)
					throw new InvalidDataException("CREDHIST entry length was invalid.");

				var blobLen = checked((int)len - 4);
				if (offset + blobLen > raw.Length)
					throw new InvalidDataException("CREDHIST entry exceeds available data.");

				var blob = raw.AsSpan(offset, blobLen).ToArray();
				offset += blobLen;

				var entry = DpapiCredHistEntry.Parse(blob);
				entries.Add(entry);
				byGuid[entry.Guid] = entry;
			}

			uint footerMagic = 0;
			Guid? currentGuid = null;
			if (offset + 4 + 16 <= raw.Length)
			{
				footerMagic = BitConverter.ToUInt32(raw, offset);
				offset += 4;

				var guidBytes = raw.AsSpan(offset, 16).ToArray();
				currentGuid = new Guid(guidBytes);
				offset += 16;
			}

			return new DpapiCredHistFile
			{
				Entries = entries,
				EntriesByGuid = byGuid,
				FooterMagic = footerMagic,
				CurrentGuid = currentGuid
			};
		}

		public bool TryDecryptChain(
			byte[] initialHash,
			out IReadOnlyList<DpapiCredHistDecryptedEntry> decryptedEntries,
			out string? failureReason)
		{
			decryptedEntries = Array.Empty<DpapiCredHistDecryptedEntry>();
			failureReason = null;

			if (initialHash == null || initialHash.Length == 0)
			{
				failureReason = "Initial hash was empty.";
				return false;
			}

			try
			{
				var curHash = initialHash;
				var results = new List<DpapiCredHistDecryptedEntry>(this.Entries.Count);

				foreach (var entry in this.Entries)
				{
					var encKey = DpapiUserKeyDerivation.DeriveLocalPreKeyFromHash(entry.UserSid, curHash);
					var clear = DpapiMasterKeyCrypto.DecryptDpapiData(
						entry.CipherAlgorithmId,
						entry.HashAlgorithmId,
						entry.Encrypted,
						encKey,
						entry.Iv,
						entry.Rounds);

					var shaLen = checked((int)entry.ShaHashLength);
					var ntLen = checked((int)entry.NtHashLength);
					if (clear.Length < shaLen + ntLen)
						throw new InvalidDataException("Decrypted CREDHIST entry was shorter than expected.");

					var pwdhash = clear.AsSpan(0, shaLen).ToArray();

					byte[]? ntHash = null;
					if (ntLen > 0)
					{
						var rawNt = clear.AsSpan(shaLen, ntLen).ToArray();
						ntHash = TrimTrailingZeros(rawNt);
						if (ntHash.Length != 16)
							ntHash = null;
					}

					results.Add(new DpapiCredHistDecryptedEntry
					{
						Guid = entry.Guid,
						UserSid = entry.UserSid,
						PasswordHash = pwdhash,
						NtHash = ntHash
					});

					// Entries are chained: the decrypted password hash becomes the keying material for the next entry.
					if (pwdhash.Length == 0)
						break;
					curHash = pwdhash;
				}

				decryptedEntries = results;
				return results.Count > 0;
			}
			catch (Exception ex)
			{
				failureReason = ex.Message;
				return false;
			}
		}

		private static byte[] TrimTrailingZeros(byte[] bytes)
		{
			var end = bytes.Length;
			while (end > 0 && bytes[end - 1] == 0)
				end--;
			return bytes.AsSpan(0, end).ToArray();
		}
	}

	internal sealed class DpapiCredHistEntry
	{
		public uint Revision { get; init; }
		public uint HashAlgorithmId { get; init; }
		public uint Rounds { get; init; }
		public uint CipherAlgorithmId { get; init; }
		public uint ShaHashLength { get; init; }
		public uint NtHashLength { get; init; }
		public byte[] Iv { get; init; } = Array.Empty<byte>();
		public string UserSid { get; init; } = string.Empty;
		public byte[] Encrypted { get; init; } = Array.Empty<byte>();
		public uint Revision2 { get; init; }
		public Guid Guid { get; init; }

		public static DpapiCredHistEntry Parse(byte[] raw)
		{
			if (raw == null || raw.Length < 64)
				throw new InvalidDataException("CREDHIST entry is too short.");

			using var stream = new MemoryStream(raw, writable: false);
			using var reader = new BinaryReader(stream, Encoding.Unicode, leaveOpen: true);

			var revision = reader.ReadUInt32();
			var hashAlgoId = reader.ReadUInt32();
			var rounds = reader.ReadUInt32();
			reader.ReadUInt32(); // unknown
			var cipherAlgoId = reader.ReadUInt32();
			var shaHashLen = reader.ReadUInt32();
			var ntHashLen = reader.ReadUInt32();
			var iv = reader.ReadBytes(16);

			var sid = DpapiRpcSid.Parse(reader).ToString();

			var clearLen = checked((int)(shaHashLen + ntHashLen));
			var blockLen = DpapiMasterKeyCrypto.GetCipherBlockLengthBytes(cipherAlgoId);
			var paddedLen = checked(clearLen + ((blockLen - (clearLen % blockLen)) % blockLen));
			if (paddedLen < 0 || paddedLen > (stream.Length - stream.Position))
				throw new InvalidDataException("CREDHIST entry encrypted length exceeds available data.");

			var encrypted = reader.ReadBytes(paddedLen);
			var revision2 = reader.ReadUInt32();
			var guidBytes = reader.ReadBytes(16);
			if (guidBytes.Length != 16)
				throw new InvalidDataException("CREDHIST entry GUID was missing.");
			var guid = new Guid(guidBytes);

			return new DpapiCredHistEntry
			{
				Revision = revision,
				HashAlgorithmId = hashAlgoId,
				Rounds = rounds,
				CipherAlgorithmId = cipherAlgoId,
				ShaHashLength = shaHashLen,
				NtHashLength = ntHashLen,
				Iv = iv,
				UserSid = sid,
				Encrypted = encrypted,
				Revision2 = revision2,
				Guid = guid
			};
		}
	}

	internal sealed record DpapiCredHistDecryptedEntry
	{
		public Guid Guid { get; init; }
		public string UserSid { get; init; } = string.Empty;
		public byte[]? PasswordHash { get; init; }
		public byte[]? NtHash { get; init; }
	}

	internal sealed class DpapiRpcSid
	{
		public byte Revision { get; init; }
		public ulong IdentifierAuthority { get; init; }
		public uint[] SubAuthorities { get; init; } = Array.Empty<uint>();

		public static DpapiRpcSid Parse(BinaryReader reader)
		{
			var revision = reader.ReadByte();
			var subAuthCount = reader.ReadByte();

			var idAuthBytes = reader.ReadBytes(6);
			if (idAuthBytes.Length != 6)
				throw new InvalidDataException("RPC_SID identifier authority was truncated.");

			ulong idAuth = 0;
			for (var i = 0; i < idAuthBytes.Length; i++)
			{
				idAuth <<= 8;
				idAuth |= idAuthBytes[i];
			}

			var subAuths = new uint[subAuthCount];
			for (var i = 0; i < subAuthCount; i++)
			{
				subAuths[i] = reader.ReadUInt32();
			}

			return new DpapiRpcSid
			{
				Revision = revision,
				IdentifierAuthority = idAuth,
				SubAuthorities = subAuths
			};
		}

		public override string ToString()
		{
			var sb = new StringBuilder();
			sb.Append("S-");
			sb.Append(this.Revision);
			sb.Append('-');
			sb.Append(this.IdentifierAuthority);

			foreach (var sa in this.SubAuthorities)
			{
				sb.Append('-');
				sb.Append(sa);
			}

			return sb.ToString();
		}
	}
}

