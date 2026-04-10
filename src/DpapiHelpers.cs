using System;
using System.Collections.Generic;
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

		internal static bool TryParseDpapiBlob(ReadOnlySpan<byte> data, out DpapiBlob blob, out string? failureReason)
		{
			blob = null!;
			failureReason = null;

			var offset = FindMagicOffset(data);
			if (offset < 0)
			{
				failureReason = "DPAPI magic header not found.";
				return false;
			}

			try
			{
				blob = DpapiBlob.Parse(data, offset);
				return true;
			}
			catch (Exception ex)
			{
				failureReason = $"Failed to parse DPAPI blob: {ex.Message}";
				return false;
			}
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

		/// <summary>
		/// Converts piped <see cref="TboDpapiMasterKeyInfo"/> objects into a GUID→cleartext dictionary.
		/// Consolidated from identical copies that existed in ChromeHelpers, MachineCertificateHelpers,
		/// SafariKeychainHelpers, and GetTBOCredManEntry.
		/// </summary>
		internal static Dictionary<Guid, byte[]> BuildMasterKeySet(
			IEnumerable<TboDpapiMasterKeyInfo>? masterKeys,
			Action<string>? logWarning,
			string context)
		{
			logWarning ??= _ => { };
			context = string.IsNullOrWhiteSpace(context) ? "BuildMasterKeySet" : context;

			if (masterKeys == null)
				return new Dictionary<Guid, byte[]>();

			var results = new Dictionary<Guid, byte[]>();
			foreach (var entry in masterKeys)
			{
				if (entry == null)
					continue;
				if (string.IsNullOrWhiteSpace(entry.MasterKeyGuid) || string.IsNullOrWhiteSpace(entry.MasterKey))
					continue;
				if (!Guid.TryParse(entry.MasterKeyGuid, out var guid))
					continue;

				byte[] keyBytes;
				try
				{
					keyBytes = BinaryHelper.ParseHexString(entry.MasterKey.AsSpan());
				}
				catch (Exception ex)
				{
					logWarning($"{context} failed to parse master key {entry.MasterKeyGuid}: {ex.Message}");
					continue;
				}

				if (keyBytes.Length == 0)
					continue;
				results[guid] = keyBytes;
			}

			return results;
		}

		/// <summary>
		/// Loads previously-decrypted DPAPI master keys for the given server from the SQLite cache.
		/// Returns an empty dictionary on any error (logged as a warning). The result is suitable
		/// for merging into a pipeline-supplied master key set — pipeline entries win on conflict.
		/// </summary>
		internal static Dictionary<Guid, byte[]> LoadCachedMasterKeys(
			string? cachePath,
			string serverName,
			Action<string> logVerbose,
			Action<string> logWarning)
		{
			try
			{
				using var db = TboCacheDatabase.Open(cachePath, logVerbose);
				var cached = db.QueryDecryptedMasterKeysByServer(serverName);
				if (cached.Count > 0)
					logVerbose($"TBO cache: loaded {cached.Count} decrypted master key(s) for {serverName}.");
				return new Dictionary<Guid, byte[]>(cached);
			}
			catch (Exception ex)
			{
				logWarning($"TBO cache: failed to load cached master keys for {serverName}: {ex.Message}");
				return new Dictionary<Guid, byte[]>();
			}
		}

		/// <summary>
		/// Merges cached master keys into a pipeline-supplied set. Pipeline entries win on GUID conflict.
		/// </summary>
		internal static void MergeMasterKeySets(
			Dictionary<Guid, byte[]> pipelineKeys,
			IReadOnlyDictionary<Guid, byte[]> cachedKeys)
		{
			foreach (var kvp in cachedKeys)
			{
				// Pipeline wins — only add cached keys for GUIDs not already present.
				pipelineKeys.TryAdd(kvp.Key, kvp.Value);
			}
		}
	}
}
