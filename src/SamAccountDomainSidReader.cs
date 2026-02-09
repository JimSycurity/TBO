using System;
using System.Buffers.Binary;
using System.Globalization;
using System.Threading;
using Titanis.Msrpc.Msrrp;
using Titanis.Winterop.Security;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal static class SamAccountDomainSidReader
	{
		private const string SamAccountVValueName = "V";

		internal static bool TryReadAccountDomainSid(
			IRegistryKey accountKey,
			CancellationToken cancellationToken,
			Action<string>? logDiagnostic,
			out SecurityIdentifier? domainSid)
		{
			domainSid = null;
			if (accountKey == null)
				throw new ArgumentNullException(nameof(accountKey));

			byte[]? bytes;
			try
			{
				var valueInfo = accountKey.GetValue(SamAccountVValueName, cancellationToken).GetAwaiter().GetResult();
				bytes = RegistryHelpers.ExtractValueBytes(valueInfo);
			}
			catch (Exception ex)
			{
				logDiagnostic?.Invoke($"Get-TBORegSamHashes: failed to read SAM account {SamAccountVValueName} value: {ex.Message}");
				return false;
			}

			if (bytes == null || bytes.Length == 0)
			{
				logDiagnostic?.Invoke("Get-TBORegSamHashes: SAM account V value is empty; cannot derive account domain SID.");
				return false;
			}

			if (!TryFindMachineDomainSid(bytes, out var sidText, out var offset))
			{
				logDiagnostic?.Invoke($"Get-TBORegSamHashes: could not locate a machine domain SID in SAM account V value (size {bytes.Length} bytes).");
				return false;
			}

			try
			{
				domainSid = SecurityIdentifier.Parse(sidText);
				logDiagnostic?.Invoke($"Get-TBORegSamHashes: SAM account domain SID derived at offset {offset.ToString(CultureInfo.InvariantCulture)}: {domainSid.ToSddlString()}.");
				return true;
			}
			catch (Exception ex)
			{
				logDiagnostic?.Invoke($"Get-TBORegSamHashes: failed to parse derived SAM domain SID '{sidText}': {ex.Message}");
				domainSid = null;
				return false;
			}
		}

		private static bool TryFindMachineDomainSid(byte[] data, out string sidText, out int offset)
		{
			sidText = string.Empty;
			offset = -1;

			// SID for local machine accounts is expected to be S-1-5-21-<a>-<b>-<c>.
			// Binary form is 24 bytes: 8-byte header + 4 subauthorities.
			if (data == null || data.Length < 24)
				return false;

			var span = data.AsSpan();
			for (int i = 0; i <= span.Length - 24; i++)
			{
				// SID header
				if (span[i + 0] != 0x01) // revision
					continue;
				if (span[i + 1] != 0x04) // subauthority count (21 + 3 domain parts)
					continue;

				// IdentifierAuthority: 6 bytes big-endian. For NT authority this is 5:
				// 00 00 00 00 00 05
				if (span[i + 2] != 0x00
					|| span[i + 3] != 0x00
					|| span[i + 4] != 0x00
					|| span[i + 5] != 0x00
					|| span[i + 6] != 0x00
					|| span[i + 7] != 0x05)
				{
					continue;
				}

				// Subauthority[0] should be 21 for machine/domain SIDs.
				var sub0 = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(i + 8, 4));
				if (sub0 != 21)
					continue;

				var sub1 = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(i + 12, 4));
				var sub2 = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(i + 16, 4));
				var sub3 = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(i + 20, 4));

				sidText = string.Format(
					CultureInfo.InvariantCulture,
					"S-1-5-21-{0}-{1}-{2}",
					sub1,
					sub2,
					sub3);
				offset = i;
				return true;
			}

			return false;
		}
	}
}

