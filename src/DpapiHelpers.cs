using System;
using System.IO;
using System.Threading;
using Titanis.Net;
using Titanis.Smb2;
using Titanis.Winterop;
using Titanis.Winterop.Security;
using Winterop = Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal static class DpapiHelpers
	{
		private static readonly SecretDecodeOptions CleartextDecodeOptions = new SecretDecodeOptions
		{
			MinTextLength = 1,
			MinAsciiCount = 1,
			MinAsciiRatio = 0.6,
			MinPrintableRatio = 0.0,
			MaxNonAsciiRatio = 1.0,
			RejectReplacementChar = true,
			AllowControlChars = false
		};

		internal static readonly byte[] DpapiMagic = new byte[]
		{
			0x01, 0x00, 0x00, 0x00, 0xD0, 0x8C, 0x9D, 0xDF, 0x01, 0x15,
			0xD1, 0x11, 0x8C, 0x7A, 0x00, 0xC0, 0x4F, 0xC2, 0x97, 0xEB
		};

		internal static int FindMagicOffset(ReadOnlySpan<byte> buffer)
		{
			if (buffer.Length < DpapiMagic.Length)
				return -1;

			return buffer.IndexOf(DpapiMagic);
		}

		internal static string NormalizeServerName(string? serverName)
		{
			return string.IsNullOrWhiteSpace(serverName)
				? string.Empty
				: serverName.TrimStart('\\');
		}

		internal static string NormalizeShareName(string? shareName)
		{
			if (string.IsNullOrWhiteSpace(shareName))
				return string.Empty;

			var trimmed = shareName.Trim();
			trimmed = trimmed.Trim('\\');
			return trimmed;
		}

		internal static byte[] ReadFileBytes(ISmbProviderInfo smb, UncPath path, CancellationToken cancellationToken)
		{
			var fileSystem = SmbFileSystemResolver.Resolve(smb);
			using var file = fileSystem.OpenFileRead(path, cancellationToken);
			using var stream = file.OpenRead();
			using var memory = new MemoryStream();
			stream.CopyTo(memory);
			return memory.ToArray();
		}

		// Locates a BK-{domain} file in the SAME directory as the given DPAPI master key file and
		// returns its bytes. Each domain-joined user has a copy of their domain's RSA backup-key
		// certificate cached in their Protect SID directory alongside their master key files
		// (Get-TBODpapiMasterKeyHashes uses the same convention to detect domain-bound key dirs).
		// Returns null when no BK-* file exists or when the directory cannot be read.
		internal static byte[]? TryReadDomainBackupKeyFileBytes(
			ISmbProviderInfo smb,
			UncPath masterKeyFilePath,
			CancellationToken cancellationToken)
		{
			var directoryPath = masterKeyFilePath.GetDirectoryPath();
			var fileSystem = SmbFileSystemResolver.Resolve(smb);
			ISmbDirectory? dir = null;
			try
			{
				dir = fileSystem.OpenDirectory(directoryPath, cancellationToken);
				foreach (var entry in dir.QueryEntries(
					"BK-*",
					Smb2Directory.Smb2DirQueryOptions.None,
					SecurityInfo.None,
					Smb2Directory.DefaultQueryBufferSize,
					cancellationToken))
				{
					if (string.IsNullOrEmpty(entry.FileName))
						continue;
					if (entry.FileName is "." or "..")
						continue;
					if ((entry.FileAttributes & Winterop.FileAttributes.Directory) != 0)
						continue;
					if (!entry.FileName.StartsWith("BK-", StringComparison.OrdinalIgnoreCase))
						continue;

					var bkPath = directoryPath.Append(entry.FileName);
					return ReadFileBytes(smb, bkPath, cancellationToken);
				}
			}
			catch (NtstatusException)
			{
				return null;
			}
			catch (System.ComponentModel.Win32Exception)
			{
				return null;
			}
			finally
			{
				dir?.Dispose();
			}

			return null;
		}

		internal static string? TryDecodeCleartext(byte[] payload)
		{
			if (payload.Length == 0)
				return null;

			var result = SecretDecoding.TryDecode(payload, CleartextDecodeOptions);
			return result.Text;
		}
	}
}
