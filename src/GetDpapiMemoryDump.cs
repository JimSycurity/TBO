using System;
using System.Collections.Generic;
using System.IO;
using System.Management.Automation;
using System.Threading;
using Titanis;
using Titanis.Net;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboDpapiMemoryDumpBlobInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string SourcePath { get; init; } = string.Empty;
		public long? FileSize { get; init; }
		public long MatchOffset { get; init; }
		public int BytesAvailable { get; init; }
		public byte[]? RawBytes { get; init; }

		public string? CredentialGuid { get; init; }
		public string? MasterKeyGuid { get; init; }
		public uint? Flags { get; init; }
		public string? Description { get; init; }
		public uint? CryptAlgorithmId { get; init; }
		public string? CryptAlgorithm { get; init; }
		public uint? HashAlgorithmId { get; init; }
		public string? HashAlgorithm { get; init; }

		public string? Cleartext { get; init; }
		public string? CleartextHex { get; init; }
		public byte[]? CleartextBytes { get; init; }
		public bool HmacValidated { get; init; }

		public string? ParseFailureReason { get; init; }
		public string? FailureReason { get; init; }
	}

	[Cmdlet(VerbsCommon.Get, "TBODpapiMemoryDump")]
	[OutputType(typeof(TboDpapiMemoryDumpBlobInfo))]
	public sealed class GetTBODpapiMemoryDump : SmbCmdlet
	{
		[Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true)]
		public string ServerName { get; set; } = string.Empty;

		[Parameter(Mandatory = true, Position = 1, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
		public string Path { get; set; } = string.Empty;

		[Parameter]
		[ValidateRange(4096, 1024 * 1024 * 1024)]
		public int ChunkBytes { get; set; } = 4 * 1024 * 1024;

		[Parameter]
		[ValidateRange(64, 1024 * 1024)]
		public int MaxBlobBytes { get; set; } = 64 * 1024;

		[Parameter]
		[ValidateRange(1, int.MaxValue)]
		public int? MaxHits { get; set; }

		[Parameter]
		public SwitchParameter Decrypt { get; set; }

		[Parameter]
		public TboDpapiMasterKeyInfo[]? MasterKeys { get; set; }

		[Parameter]
		public string? Entropy { get; set; }

		[Parameter]
		public byte[]? EntropyBytes { get; set; }

		[Parameter]
		public SwitchParameter IncludeRawBytes { get; set; }

		[Parameter]
		public SwitchParameter Cache { get; set; }

		[Parameter]
		public string? CachePath { get; set; }

		private CancellationTokenSource? _cancelSource;

		protected override void ProcessRecord(ISmbProviderInfo smb)
		{
			this._cancelSource ??= new CancellationTokenSource();
			var cancellationToken = this._cancelSource.Token;

			var serverName = DpapiHelpers.NormalizeServerName(this.ServerName);
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("ServerName must be provided.", nameof(this.ServerName));

			if (this.MaxBlobBytes < DpapiHelpers.DpapiMagic.Length)
				throw new ArgumentOutOfRangeException(nameof(this.MaxBlobBytes), "MaxBlobBytes must be >= the DPAPI magic header size.");

			var uncPath = ResolveToUncPath(this.Path, nameof(this.Path));
			if (string.IsNullOrEmpty(uncPath.ShareName))
				throw new ArgumentException($"Path must include a share name: {uncPath}", nameof(this.Path));

			if (!string.IsNullOrEmpty(uncPath.ServerName)
				&& !uncPath.ServerName.Equals(serverName, StringComparison.OrdinalIgnoreCase))
				throw new ArgumentException($"ServerName '{serverName}' does not match UNC host '{uncPath.ServerName}'.", nameof(this.ServerName));

			var entropy = ResolveEntropy();

			var masterKeySet = DpapiHelpers.BuildMasterKeySet(this.MasterKeys, msg => this.LogWarning(smb, msg), "Get-TBODpapiMemoryDump");
			var ingestCache = this.ResolveCacheIngestionEnabled(this.Cache);
			if (ingestCache)
			{
				var cached = DpapiHelpers.LoadCachedMasterKeys(this.CachePath, serverName, msg => this.LogVerbose(smb, msg), msg => this.LogWarning(smb, msg));
				DpapiHelpers.MergeMasterKeySets(masterKeySet, cached);
			}
			if (masterKeySet.Count > 0)
				TboDpapiMasterKeyCache.TrySetMany(smb, serverName, masterKeySet);
			TboCacheDatabase? cacheDb = null;
			long cacheMachineId = 0;
			try
			{
				if (ingestCache)
				{
					try
					{
						cacheDb = TboCacheDatabase.Open(this.CachePath, msg => this.WriteVerbose(msg));
						cacheMachineId = cacheDb.UpsertMachine(serverName);
					}
					catch (Exception ex)
					{
						cacheDb?.Dispose();
						cacheDb = null;
						cacheMachineId = 0;
						this.LogException(smb, $"Get-TBODpapiMemoryDump failed to open cache DB for {serverName}", ex, emitWarning: false);
						this.LogWarning(smb, $"Get-TBODpapiMemoryDump cache write disabled: {ex.Message}");
					}
				}

				var fileSystem = SmbFileSystemResolver.Resolve(smb);
				using var file = fileSystem.OpenFileRead(uncPath, cancellationToken);
				using var stream = file.OpenRead();

				long? fileSize = null;
				try
				{
					if (stream.CanSeek)
						fileSize = stream.Length;
				}
				catch
				{
					fileSize = null;
				}

				ScanDumpStream(
					smb,
					serverName,
					uncPath.ToString(),
					fileSize,
					stream,
					masterKeySet,
					entropy,
					cacheDb,
					cacheMachineId,
					cancellationToken);
			}
			finally
			{
				cacheDb?.Dispose();
			}
		}

		protected override void StopProcessing()
		{
			this._cancelSource?.Cancel();
			base.StopProcessing();
		}

		private void ScanDumpStream(
			ISmbProviderInfo smb,
			string serverName,
			string dumpPath,
			long? fileSize,
			Stream stream,
			IReadOnlyDictionary<Guid, byte[]> masterKeySet,
			byte[]? entropy,
			TboCacheDatabase? cacheDb,
			long cacheMachineId,
			CancellationToken cancellationToken)
		{
			if (stream == null)
				throw new ArgumentNullException(nameof(stream));

			var magic = DpapiHelpers.DpapiMagic;
			var maxBlobBytes = this.MaxBlobBytes;
			var maxHits = this.MaxHits;
			var decrypt = this.Decrypt.IsPresent;

			var progressId = 44;
			var progressActivity = $"Scanning memory dump for DPAPI blobs on {serverName}";

			this.WriteProgressUpdate(progressId, progressActivity, $"Scanning {dumpPath}", fileSize, 0);

			var overlapLen = Math.Max(magic.Length - 1, maxBlobBytes);
			var buffer = new byte[overlapLen + this.ChunkBytes];
			int bufferedCount = 0;

			long filePos = 0;
			long nextScanOffset = 0;
			int hits = 0;

			while (true)
			{
				cancellationToken.ThrowIfCancellationRequested();

				int read;
				try
				{
					read = stream.Read(buffer, bufferedCount, this.ChunkBytes);
				}
				catch (Exception ex)
				{
					this.LogException(smb, $"Get-TBODpapiMemoryDump failed to read {dumpPath}", ex);
					return;
				}

				if (read <= 0)
					break;

				filePos += read;
				var total = bufferedCount + read;
				var bufferStartOffset = filePos - total;

				var scanLimitAbs = filePos - maxBlobBytes;
				if (scanLimitAbs < 0)
					scanLimitAbs = 0;

				if (scanLimitAbs > nextScanOffset)
				{
					var scanLimitRel = checked((int)(scanLimitAbs - bufferStartOffset));
					scanLimitRel = Math.Clamp(scanLimitRel, 0, total);

					var startIdx = checked((int)(nextScanOffset - bufferStartOffset));
					startIdx = Math.Clamp(startIdx, 0, total);

					if (scanLimitRel > startIdx)
					{
						ScanBufferWindow(
							smb,
							serverName,
							dumpPath,
							fileSize,
							buffer.AsSpan(0, total),
							bufferStartOffset,
							startIdx,
							scanLimitRel,
							magic,
							maxBlobBytes,
							decrypt,
							masterKeySet,
							entropy,
							cacheDb,
							cacheMachineId,
							ref hits,
							maxHits,
							cancellationToken);

						if (maxHits.HasValue && hits >= maxHits.Value)
							break;
					}

					nextScanOffset = bufferStartOffset + scanLimitRel;
				}

				this.WriteProgressUpdate(progressId, progressActivity, $"Scanning {dumpPath}", fileSize, filePos);

				bufferedCount = Math.Min(overlapLen, total);
				if (bufferedCount > 0)
					Array.Copy(buffer, total - bufferedCount, buffer, 0, bufferedCount);
			}

			// Final scan: include matches near end-of-file (may not have enough lookahead for full parsing/decryption).
			if (!(maxHits.HasValue && hits >= maxHits.Value) && bufferedCount > 0)
			{
				var total = bufferedCount;
				var bufferStartOffset = filePos - total;
				var finalLimitAbs = filePos - magic.Length + 1;
				if (finalLimitAbs < 0)
					finalLimitAbs = 0;

				if (finalLimitAbs > nextScanOffset)
				{
					var scanLimitRel = checked((int)(finalLimitAbs - bufferStartOffset));
					scanLimitRel = Math.Clamp(scanLimitRel, 0, total);

					var startIdx = checked((int)(nextScanOffset - bufferStartOffset));
					startIdx = Math.Clamp(startIdx, 0, total);

					if (scanLimitRel > startIdx)
					{
						ScanBufferWindow(
							smb,
							serverName,
							dumpPath,
							fileSize,
							buffer.AsSpan(0, total),
							bufferStartOffset,
							startIdx,
							scanLimitRel,
							magic,
							maxBlobBytes,
							decrypt,
							masterKeySet,
							entropy,
							cacheDb,
							cacheMachineId,
							ref hits,
							maxHits,
							cancellationToken,
							endOfFile: true);
					}
				}
			}

			this.WriteProgress(new ProgressRecord(progressId, progressActivity, "Completed")
			{
				RecordType = ProgressRecordType.Completed
			});
		}

		private void ScanBufferWindow(
			ISmbProviderInfo smb,
			string serverName,
			string dumpPath,
			long? fileSize,
			ReadOnlySpan<byte> buffer,
			long bufferStartOffset,
			int startIdx,
			int scanLimitRel,
			ReadOnlySpan<byte> magic,
			int maxBlobBytes,
			bool decrypt,
			IReadOnlyDictionary<Guid, byte[]> masterKeySet,
			byte[]? entropy,
			TboCacheDatabase? cacheDb,
			long cacheMachineId,
			ref int hits,
			int? maxHits,
			CancellationToken cancellationToken,
			bool endOfFile = false)
		{
			// Ensure IndexOf can match patterns starting up to scanLimitRel-1.
			var searchLen = (scanLimitRel - startIdx) + magic.Length - 1;
			if (searchLen <= 0)
				return;
			if (searchLen > buffer.Length - startIdx)
				searchLen = buffer.Length - startIdx;

			var searchSpan = buffer.Slice(startIdx, searchLen);
			var searchPos = 0;
			while (true)
			{
				cancellationToken.ThrowIfCancellationRequested();

				var found = searchSpan.Slice(searchPos).IndexOf(magic);
				if (found < 0)
					break;

				found += searchPos;
				var matchIdx = startIdx + found;
				var matchOffset = bufferStartOffset + matchIdx;

				// Guard against over-scanning due to clamping in the EOF case.
				if (matchIdx >= scanLimitRel)
					break;

				if (maxHits.HasValue && hits >= maxHits.Value)
					return;

				var available = buffer.Length - matchIdx;
				var candidateLen = endOfFile ? Math.Min(maxBlobBytes, available) : maxBlobBytes;
				if (candidateLen <= 0)
				{
					searchPos = found + 1;
					continue;
				}

				var candidate = buffer.Slice(matchIdx, candidateLen);
				EmitBlobHit(
					smb,
					serverName,
					dumpPath,
					fileSize,
					matchOffset,
					candidateLen,
					candidate,
					decrypt,
					masterKeySet,
					entropy,
					cacheDb,
					cacheMachineId);

				hits++;

				// Advance by one byte to allow overlapping matches (unlikely, but cheap).
				searchPos = found + 1;
			}
		}

		private void EmitBlobHit(
			ISmbProviderInfo smb,
			string serverName,
			string dumpPath,
			long? fileSize,
			long matchOffset,
			int candidateLen,
			ReadOnlySpan<byte> candidate,
			bool decrypt,
			IReadOnlyDictionary<Guid, byte[]> masterKeySet,
			byte[]? entropy,
			TboCacheDatabase? cacheDb,
			long cacheMachineId)
		{
			string? credentialGuid = null;
			string? masterKeyGuid = null;
			uint? flags = null;
			string? description = null;
			uint? cryptAlgorithmId = null;
			string? cryptAlgorithm = null;
			uint? hashAlgorithmId = null;
			string? hashAlgorithm = null;
			string? parseFailureReason = null;

			if (DpapiBlobCrypto.TryParseHeader(candidate, 0, out var header, out var headerFailure))
			{
				credentialGuid = header.GuidCredential.ToString();
				masterKeyGuid = header.GuidMasterKey.ToString();
				flags = header.Flags;
				description = header.Description;

				if (header.CryptAlgorithm.HasValue && header.CryptAlgorithmLength.HasValue)
				{
					cryptAlgorithmId = header.CryptAlgorithm.Value;
					cryptAlgorithm = DpapiBlobCrypto.ResolveCipherAlgorithmName(header.CryptAlgorithm.Value, header.CryptAlgorithmLength.Value);
				}

				if (header.HashAlgorithm.HasValue && header.HashAlgorithmLength.HasValue)
				{
					hashAlgorithmId = header.HashAlgorithm.Value;
					hashAlgorithm = DpapiBlobCrypto.ResolveHashAlgorithmName(header.HashAlgorithm.Value, header.HashAlgorithmLength.Value);
				}

				parseFailureReason = headerFailure;
			}
			else
			{
				parseFailureReason = headerFailure;
			}

			byte[]? rawBytes = null;
			byte[]? cleartextBytes = null;
			string? cleartextText = null;
			string? failureReason = null;
			bool hmacValidated = false;

			var parseBlob = decrypt || this.IncludeRawBytes.IsPresent;
			if (parseBlob)
			{
				DpapiBlob blob;
				try
				{
					blob = DpapiBlob.Parse(candidate, 0);
					rawBytes = this.IncludeRawBytes.IsPresent ? blob.RawData : null;
				}
				catch (Exception ex)
				{
					failureReason = $"Failed to parse DPAPI blob: {ex.Message}";
					blob = null!;
				}

				if (failureReason == null && decrypt)
				{
					byte[]? masterKey = null;
					if (masterKeySet.TryGetValue(blob.GuidMasterKey, out var explicitKey) && explicitKey != null && explicitKey.Length > 0)
					{
						masterKey = explicitKey;
					}
					else if (!TboDpapiMasterKeyCache.TryGet(smb, serverName, blob.GuidMasterKey, out masterKey) || masterKey == null || masterKey.Length == 0)
					{
						masterKey = null;
					}

					if (masterKey == null || masterKey.Length == 0)
					{
						failureReason = $"Master key {blob.GuidMasterKey} was not found in the supplied key set or cache.";
					}
					else
					{
						var result = DpapiBlobCrypto.Decrypt(blob, masterKey, entropy);
						cleartextBytes = result.Cleartext;
						cleartextText = cleartextBytes != null ? DpapiHelpers.TryDecodeCleartext(cleartextBytes) : null;
						hmacValidated = result.HmacValidated;
						failureReason = result.FailureReason;

						if (cacheDb != null && cacheMachineId > 0 && cleartextBytes != null && cleartextBytes.Length > 0 && cleartextText != null)
						{
							TryCacheCleartextCredential(smb, cacheDb, cacheMachineId, dumpPath, matchOffset, blob.GuidMasterKey, cleartextBytes);
						}
					}
				}
			}

			if (cacheDb != null && cacheMachineId > 0)
			{
				var blobKey = $"MemoryDump|{dumpPath}|{matchOffset}";
				try
				{
					cacheDb.UpsertDpapiBlob(
						machineId: cacheMachineId,
						blobKey: blobKey,
						source: "MemoryDump",
						path: dumpPath,
						valueName: null,
						valueType: null,
						dataLength: null,
						fileSize: fileSize,
						matchOffset: matchOffset,
						bytesScanned: candidateLen,
						credentialGuid: credentialGuid,
						masterKeyGuid: masterKeyGuid,
						flags: flags,
						description: description,
						cryptAlgorithmId: cryptAlgorithmId,
						hashAlgorithmId: hashAlgorithmId,
						parseFailureReason: parseFailureReason);
				}
				catch (Exception ex)
				{
					this.LogException(smb, $"Get-TBODpapiMemoryDump failed to write cache blob record for {serverName}", ex, emitWarning: false);
					this.LogWarning(smb, $"Get-TBODpapiMemoryDump cache write failed: {ex.Message}");
				}
			}

			this.WriteObject(new TboDpapiMemoryDumpBlobInfo
			{
				ServerName = serverName,
				SourcePath = dumpPath,
				FileSize = fileSize,
				MatchOffset = matchOffset,
				BytesAvailable = candidateLen,
				RawBytes = rawBytes,

				CredentialGuid = credentialGuid,
				MasterKeyGuid = masterKeyGuid,
				Flags = flags,
				Description = description,
				CryptAlgorithmId = cryptAlgorithmId,
				CryptAlgorithm = cryptAlgorithm,
				HashAlgorithmId = hashAlgorithmId,
				HashAlgorithm = hashAlgorithm,

				Cleartext = cleartextText,
				CleartextHex = cleartextBytes?.ToHexString(),
				CleartextBytes = cleartextBytes,
				HmacValidated = hmacValidated,

				ParseFailureReason = parseFailureReason,
				FailureReason = failureReason
			});
		}

		private void TryCacheCleartextCredential(
			ISmbProviderInfo smb,
			TboCacheDatabase db,
			long machineId,
			string dumpPath,
			long matchOffset,
			Guid masterKeyGuid,
			byte[] cleartextBytes)
		{
			if (db == null)
				return;
			if (machineId <= 0)
				return;
			if (cleartextBytes == null || cleartextBytes.Length == 0)
				return;

			// Avoid bloating the cache with large binary payloads.
			const int MaxCacheBytes = 8192;
			var payload = cleartextBytes.Length <= MaxCacheBytes ? cleartextBytes : cleartextBytes.AsSpan(0, MaxCacheBytes).ToArray();

			try
			{
				var kind = "dpapi_cleartext";
				var identifier = $"{dumpPath}|{matchOffset}|{masterKeyGuid}";
				var credentialId = db.UpsertCredential(kind, identifier, payload);
				db.InsertObservation(
					machineId: machineId,
					principalId: null,
					credentialId: credentialId,
					sourceKind: "Get-TBODpapiMemoryDump",
					sourcePath: dumpPath,
					contextJson: $"{{\"offset\":{matchOffset.ToString(System.Globalization.CultureInfo.InvariantCulture)},\"masterKeyGuid\":\"{masterKeyGuid}\"}}",
					confidence: 60);
			}
			catch (Exception ex)
			{
				this.LogException(smb, $"Get-TBODpapiMemoryDump failed to write cache credential record for {this.ServerName}", ex, emitWarning: false);
			}
		}

		private byte[]? ResolveEntropy()
		{
			if (this.EntropyBytes != null && this.EntropyBytes.Length > 0)
				return this.EntropyBytes;
			if (!string.IsNullOrWhiteSpace(this.Entropy))
				return BinaryHelper.ParseHexString(this.Entropy.AsSpan());
			return null;
		}

		private void WriteProgressUpdate(int progressId, string activity, string status, long? fileSize, long bytesScanned)
		{
			int percent = 0;
			if (fileSize.HasValue && fileSize.Value > 0)
			{
				try
				{
					percent = (int)Math.Clamp((bytesScanned * 100.0) / fileSize.Value, 0.0, 100.0);
				}
				catch
				{
					percent = 0;
				}
			}

			var record = new ProgressRecord(progressId, activity, status)
			{
				RecordType = ProgressRecordType.Processing,
				PercentComplete = percent
			};

			this.WriteProgress(record);
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
	}
}
