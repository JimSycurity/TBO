using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Titanis;
using Titanis.Net;
using Titanis.Smb2;
using Titanis.Winterop;
using Titanis.Winterop.Security;
using Winterop = Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboDpapiCredHistEntryInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string ShareName { get; init; } = string.Empty;
		public string? UserName { get; init; }
		public string? UserSid { get; init; }

		public string CredHistPath { get; init; } = string.Empty;
		public uint FooterMagic { get; init; }
		public string? CurrentGuid { get; init; }
		public string? StartHashLabel { get; init; }

		public int EntryIndex { get; init; }
		public string? EntryGuid { get; init; }
		public bool? IsCurrent { get; init; }
		public string? PasswordHashHex { get; init; }
		public string? NtHashHex { get; init; }

		public string? FailureReason { get; init; }
	}

	[Cmdlet(VerbsCommon.Get, "TBODpapiCredHist")]
	[OutputType(typeof(TboDpapiCredHistEntryInfo))]
	public sealed class GetTBODpapiCredHist : SmbCmdlet
	{
		[Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true)]
		public string ServerName { get; set; } = string.Empty;

		[Parameter]
		public string ShareName { get; set; } = DpapiMasterKeyLocator.DefaultShareName;

		[Parameter]
		public string[]? UserName { get; set; }

		[Parameter]
		public string? UserPassword { get; set; }

		[Parameter]
		public string? UserNtlmHash { get; set; }

		/// <summary>
		/// When set, persists the password/NT hash used to decrypt CREDHIST (and the hashes recovered
		/// from within the decrypted chain) to the TBO cache's <c>verified_password_hashes</c> table
		/// for reuse by later cmdlet runs. Cache reads are always attempted when cache ingestion is
		/// enabled — see <c>ResolveCacheIngestionEnabled</c>.
		/// </summary>
		[Parameter]
		public SwitchParameter Cache { get; set; }

		/// <summary>
		/// Optional explicit path to the TBO cache SQLite file. Overrides the
		/// <c>TITANIS_TBO_CACHE</c> environment variable and the default per-user path.
		/// </summary>
		[Parameter]
		public string? CachePath { get; set; }

		private const string CacheCmdletName = "Get-TBODpapiCredHist";
		private const string VerifiedViaCredHistChain = "credhist_chain_decrypt";
		private const string VerifiedViaCredHistEntry = "credhist_entry";

		private CancellationTokenSource? _cancelSource;

		protected override void ProcessRecord(ISmbProviderInfo smb)
		{
			this._cancelSource ??= new CancellationTokenSource();
			var cancellationToken = this._cancelSource.Token;

			var serverName = DpapiHelpers.NormalizeServerName(this.ServerName);
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("ServerName must be provided.", nameof(this.ServerName));

			var shareName = DpapiHelpers.NormalizeShareName(this.ShareName);
			if (string.IsNullOrWhiteSpace(shareName))
				throw new ArgumentException("ShareName must be provided.", nameof(this.ShareName));

			var plaintextStartHashes = ResolveStartHashes();

			// Load cached verified hashes for the server once; per-file logic augments its own
			// start-hash list with the entries for that file's SID.
			var cacheIngestEnabled = this.ResolveCacheIngestionEnabled(this.Cache);
			var cachedHashesBySid = new Dictionary<string, List<(string Label, byte[] Hash, string HashType)>>(StringComparer.OrdinalIgnoreCase);
			if (cacheIngestEnabled)
			{
				LoadCachedHashes(serverName, cachedHashesBySid);
			}

			if (plaintextStartHashes.Count == 0 && cachedHashesBySid.Count == 0)
			{
				this.WriteWarning("Get-TBODpapiCredHist requires UserPassword/UserNtlmHash (or cached verified hashes) to decrypt CREDHIST.");
				return;
			}

			var userFilters = ChromeHelpers.BuildUserFilters(this.UserName);
			var userDirs = ChromeHelpers.EnumerateUserDirectories(
				smb,
				serverName,
				shareName,
				userFilters,
				message => this.LogWarning(smb, message),
				message => this.LogVerbose(smb, message),
				(context, ex) => this.LogException(smb, context, ex),
				cancellationToken);

			foreach (var userDirName in userDirs)
			{
				ProcessProtectRoot(
					smb,
					serverName,
					shareName,
					userDirName,
					UncPath.Parse($@"\\{serverName}\{shareName}\Users\{userDirName}\AppData\Roaming\Microsoft\Protect"),
					plaintextStartHashes,
					cacheIngestEnabled,
					cachedHashesBySid,
					cancellationToken);

				ProcessProtectRoot(
					smb,
					serverName,
					shareName,
					userDirName,
					UncPath.Parse($@"\\{serverName}\{shareName}\Users\{userDirName}\AppData\Local\Microsoft\Protect"),
					plaintextStartHashes,
					cacheIngestEnabled,
					cachedHashesBySid,
					cancellationToken);
			}
		}

		protected override void StopProcessing()
		{
			this._cancelSource?.Cancel();
			base.StopProcessing();
		}

		private List<(string Label, byte[] Hash, string HashType)> ResolveStartHashes()
		{
			byte[]? userNtHash = null;
			if (!string.IsNullOrWhiteSpace(this.UserNtlmHash))
			{
				try
				{
					userNtHash = NtlmHashInput.Parse(this.UserNtlmHash).NtHash;
				}
				catch (Exception ex)
				{
					throw new ArgumentException($"UserNtlmHash was invalid: {ex.Message}", nameof(this.UserNtlmHash), ex);
				}
			}

			byte[]? userSha1Hash = null;
			byte[]? userNtHashFromPassword = null;
			if (!string.IsNullOrWhiteSpace(this.UserPassword))
			{
				var pwdUtf16 = Encoding.Unicode.GetBytes(this.UserPassword);
				userSha1Hash = SHA1.HashData(pwdUtf16);

				if (userNtHash == null)
				{
					userNtHashFromPassword = Titanis.Crypto.SlimHashAlgorithm
						.ComputeHash<Titanis.Crypto.Md4Context>(pwdUtf16);
				}
			}

			var candidates = new List<(string Label, byte[] Hash, string HashType)>();
			if (userSha1Hash != null && userSha1Hash.Length > 0)
				candidates.Add(("SHA1(password)", userSha1Hash, DpapiVerifiedHashTypes.Sha1Pwd));
			if (userNtHash != null && userNtHash.Length > 0)
				candidates.Add(("UserNtlmHash", userNtHash, DpapiVerifiedHashTypes.NtPwd));
			if (userNtHashFromPassword != null && userNtHashFromPassword.Length > 0)
				candidates.Add(("NT(password)", userNtHashFromPassword, DpapiVerifiedHashTypes.NtPwd));

			return candidates
				.GroupBy(x => x.HashType + ":" + Convert.ToHexString(x.Hash), StringComparer.OrdinalIgnoreCase)
				.Select(g => g.First())
				.ToList();
		}

		private void ProcessProtectRoot(
			ISmbProviderInfo smb,
			string serverName,
			string shareName,
			string userDirName,
			UncPath protectRoot,
			IReadOnlyList<(string Label, byte[] Hash, string HashType)> plaintextStartHashes,
			bool cacheIngestEnabled,
			IReadOnlyDictionary<string, List<(string Label, byte[] Hash, string HashType)>> cachedHashesBySid,
			CancellationToken cancellationToken)
		{
			var fileSystem = SmbFileSystemResolver.Resolve(smb);
			ISmbDirectory? dir = null;

			try
			{
				dir = fileSystem.OpenDirectory(protectRoot, cancellationToken);
				foreach (var entry in dir.QueryEntries("*", Smb2Directory.Smb2DirQueryOptions.QueryReparseInfo, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken))
				{
					if (string.IsNullOrEmpty(entry.FileName))
						continue;
					if (entry.FileName is "." or "..")
						continue;

					bool isDirectory = (entry.FileAttributes & Winterop.FileAttributes.Directory) != 0;
					bool isReparse = (entry.FileAttributes & Winterop.FileAttributes.ReparsePoint) != 0;
					if (!isDirectory || isReparse)
						continue;
					if (!SidPattern.IsMatch(entry.FileName))
						continue;

					var sidDir = protectRoot.Append(entry.FileName);
					var credHistPath = sidDir.Append("CREDHIST");

					byte[] bytes;
					try
					{
						bytes = DpapiHelpers.ReadFileBytes(smb, credHistPath, cancellationToken);
					}
					catch (NtstatusException ex) when (ChromeHelpers.IsMissingPath(ex))
					{
						continue;
					}
					catch (NtstatusException ex) when (ChromeHelpers.IsAccessDenied(ex))
					{
						this.LogVerbose(smb, $"Get-TBODpapiCredHist access denied reading {credHistPath}: {ex.StatusCode}.");
						continue;
					}
					catch (Exception ex)
					{
						this.LogException(smb, $"Get-TBODpapiCredHist failed to read {credHistPath}", ex, emitWarning: false);
						this.WriteObject(new TboDpapiCredHistEntryInfo
						{
							ServerName = this.ServerName,
							ShareName = this.ShareName,
							UserName = userDirName,
							UserSid = entry.FileName,
							CredHistPath = credHistPath.ToString(),
							FailureReason = $"Failed to read CREDHIST: {ex.Message}"
						});
						continue;
					}

					DpapiCredHistFile credHistFile;
					try
					{
						credHistFile = DpapiCredHistFile.Parse(bytes);
					}
					catch (Exception ex)
					{
						this.WriteObject(new TboDpapiCredHistEntryInfo
						{
							ServerName = this.ServerName,
							ShareName = this.ShareName,
							UserName = userDirName,
							UserSid = entry.FileName,
							CredHistPath = credHistPath.ToString(),
							FailureReason = $"Failed to parse CREDHIST: {ex.Message}"
						});
						continue;
					}

					// Per-SID start hash list: plaintext (always) plus any cached entries for this
					// file's SID. Deduplicated by HashType:HashHex so that overlap is silently dropped.
					var fileSid = entry.FileName;
					var perFileStartHashes = new List<(string Label, byte[] Hash, string HashType)>(plaintextStartHashes);
					if (cachedHashesBySid.TryGetValue(fileSid, out var cachedForSid))
					{
						if (cachedForSid.Count > 0)
							this.WriteVerbose($"Get-TBODpapiCredHist: augmenting start hashes for SID {fileSid} with {cachedForSid.Count} cached entry/entries.");
						perFileStartHashes.AddRange(cachedForSid);
					}

					perFileStartHashes = perFileStartHashes
						.GroupBy(x => x.HashType + ":" + Convert.ToHexString(x.Hash), StringComparer.OrdinalIgnoreCase)
						.Select(g => g.First())
						.ToList();

					string? usedLabel = null;
					string? usedHashType = null;
					byte[]? usedStartHash = null;
					string? failureReason = null;
					IReadOnlyList<DpapiCredHistDecryptedEntry> decryptedEntries = Array.Empty<DpapiCredHistDecryptedEntry>();

					foreach (var (label, startHash, hashType) in perFileStartHashes)
					{
						if (credHistFile.TryDecryptChain(startHash, out decryptedEntries, out failureReason))
						{
							usedLabel = label;
							usedHashType = hashType;
							usedStartHash = startHash;
							break;
						}
					}

					if (decryptedEntries != null && decryptedEntries.Count > 0)
					{
						var currentGuidText = credHistFile.CurrentGuid?.ToString();

						// Cache write: (1) the winning start hash — verified by a successful chain
						// decrypt — and (2) every PasswordHash/NtHash recovered from inside the chain.
						// Historical hashes verify historical master keys so they're just as useful
						// to later cmdlets and the planned triage cmdlet (TBO-txp).
						if (cacheIngestEnabled && usedStartHash != null && usedHashType != null)
						{
							CacheVerifiedHashes(
								serverName,
								fileSid,
								userDirName,
								usedStartHash,
								usedHashType,
								decryptedEntries,
								credHistPath.ToString());
						}

						for (int i = 0; i < decryptedEntries.Count; i++)
						{
							var dec = decryptedEntries[i];
							var isCurrent = credHistFile.CurrentGuid.HasValue && credHistFile.CurrentGuid.Value == dec.Guid;

							this.WriteObject(new TboDpapiCredHistEntryInfo
							{
								ServerName = this.ServerName,
								ShareName = this.ShareName,
								UserName = userDirName,
								UserSid = dec.UserSid,
								CredHistPath = credHistPath.ToString(),
								FooterMagic = credHistFile.FooterMagic,
								CurrentGuid = currentGuidText,
								StartHashLabel = usedLabel,
								EntryIndex = i,
								EntryGuid = dec.Guid.ToString(),
								IsCurrent = isCurrent,
								PasswordHashHex = dec.PasswordHash?.ToHexString(),
								NtHashHex = dec.NtHash?.ToHexString()
							});
						}
					}
					else
					{
						var tried = perFileStartHashes.Count == 0
							? "(none)"
							: string.Join(", ", perFileStartHashes.Select(s => s.Label));
						this.WriteObject(new TboDpapiCredHistEntryInfo
						{
							ServerName = this.ServerName,
							ShareName = this.ShareName,
							UserName = userDirName,
							UserSid = fileSid,
							CredHistPath = credHistPath.ToString(),
							FooterMagic = credHistFile.FooterMagic,
							CurrentGuid = credHistFile.CurrentGuid?.ToString(),
							FailureReason = $"Failed to decrypt CREDHIST (tried {tried}): {failureReason ?? "unknown error"}"
						});
					}
				}
			}
			catch (NtstatusException ex) when (ChromeHelpers.IsMissingPath(ex))
			{
				this.LogVerbose(smb, $"Get-TBODpapiCredHist could not open {protectRoot}: {ex.StatusCode}.");
			}
			catch (NtstatusException ex) when (ChromeHelpers.IsAccessDenied(ex))
			{
				this.LogVerbose(smb, $"Get-TBODpapiCredHist access denied opening {protectRoot}: {ex.StatusCode}.");
			}
			catch (Exception ex)
			{
				this.LogException(smb, $"Get-TBODpapiCredHist failed to enumerate {protectRoot}", ex);
				throw;
			}
			finally
			{
				if (dir != null)
					dir.Dispose();
			}
		}

		private static readonly Regex SidPattern = new(
			@"^S-1-\d+(-\d+)+$",
			RegexOptions.Compiled | RegexOptions.IgnoreCase);

		/// <summary>
		/// Reads verified hashes for <paramref name="serverName"/> and populates
		/// <paramref name="target"/> keyed by user SID. Failures are swallowed after logging so a
		/// cache miss never breaks the cmdlet.
		/// </summary>
		private void LoadCachedHashes(
			string serverName,
			Dictionary<string, List<(string Label, byte[] Hash, string HashType)>> target)
		{
			TboCacheDatabase? cacheDb = null;
			try
			{
				cacheDb = TboCacheDatabase.Open(this.CachePath, msg => this.WriteVerbose(msg));
				var rows = cacheDb.QueryVerifiedPasswordHashes(serverName, userSid: null);
				foreach (var row in rows)
				{
					byte[] parsed;
					try
					{
						parsed = Convert.FromHexString(row.HashValueHex);
					}
					catch (FormatException ex)
					{
						this.WriteVerbose($"Get-TBODpapiCredHist: skipping malformed cached hash for {row.UserSid} ({row.HashType}): {ex.Message}");
						continue;
					}

					if (row.HashType != DpapiVerifiedHashTypes.Sha1Pwd
						&& row.HashType != DpapiVerifiedHashTypes.NtPwd)
					{
						this.WriteVerbose($"Get-TBODpapiCredHist: skipping unknown cached hash type '{row.HashType}' for SID {row.UserSid}.");
						continue;
					}

					if (!target.TryGetValue(row.UserSid, out var list))
					{
						list = new List<(string, byte[], string)>();
						target[row.UserSid] = list;
					}

					list.Add(($"cache:{row.HashType}", parsed, row.HashType));
				}

				if (target.Count > 0)
					this.WriteVerbose($"Get-TBODpapiCredHist: loaded cached verified hashes for {target.Count} SID(s) on {serverName}.");
			}
			catch (Exception ex)
			{
				this.WriteWarning($"Get-TBODpapiCredHist: cache read failed for {serverName}: {ex.Message}");
			}
			finally
			{
				cacheDb?.Dispose();
			}
		}

		/// <summary>
		/// Persists the winning start hash and all recovered historical hashes from a decrypted
		/// CREDHIST chain to the TBO cache. Failures are logged and swallowed — a cache write must
		/// never break the enumeration.
		/// </summary>
		private void CacheVerifiedHashes(
			string serverName,
			string userSid,
			string? userDirName,
			byte[] startHash,
			string startHashType,
			IReadOnlyList<DpapiCredHistDecryptedEntry> decryptedEntries,
			string contextForErrors)
		{
			TboCacheDatabase? cacheDb = null;
			try
			{
				cacheDb = TboCacheDatabase.Open(this.CachePath, msg => this.WriteVerbose(msg));
				var machineId = cacheDb.UpsertMachine(serverName);
				var writeCount = 0;

				// (1) The start hash that decrypted the chain — the current password's hash.
				cacheDb.UpsertVerifiedPasswordHash(
					machineId: machineId,
					serverName: serverName,
					userSid: userSid,
					userName: userDirName,
					hashType: startHashType,
					hashValueHex: Convert.ToHexString(startHash),
					verifiedByCmdlet: CacheCmdletName,
					verifiedVia: VerifiedViaCredHistChain);
				writeCount++;

				// (2) Every PasswordHash/NtHash recovered from inside the chain — historical
				// passwords that each decrypt historical master keys. Same (user_sid) as the
				// current entry since CREDHIST is per-user.
				foreach (var dec in decryptedEntries)
				{
					if (dec.PasswordHash != null && dec.PasswordHash.Length > 0)
					{
						cacheDb.UpsertVerifiedPasswordHash(
							machineId: machineId,
							serverName: serverName,
							userSid: userSid,
							userName: userDirName,
							hashType: DpapiVerifiedHashTypes.Sha1Pwd,
							hashValueHex: Convert.ToHexString(dec.PasswordHash),
							verifiedByCmdlet: CacheCmdletName,
							verifiedVia: VerifiedViaCredHistEntry);
						writeCount++;
					}

					if (dec.NtHash != null && dec.NtHash.Length == 16)
					{
						cacheDb.UpsertVerifiedPasswordHash(
							machineId: machineId,
							serverName: serverName,
							userSid: userSid,
							userName: userDirName,
							hashType: DpapiVerifiedHashTypes.NtPwd,
							hashValueHex: Convert.ToHexString(dec.NtHash),
							verifiedByCmdlet: CacheCmdletName,
							verifiedVia: VerifiedViaCredHistEntry);
						writeCount++;
					}
				}

				this.WriteVerbose($"Get-TBODpapiCredHist: cached {writeCount} verified hash(es) for SID {userSid} on {serverName}.");
			}
			catch (Exception ex)
			{
				this.WriteWarning($"Get-TBODpapiCredHist: cache write failed for {contextForErrors}: {ex.Message}");
			}
			finally
			{
				cacheDb?.Dispose();
			}
		}
	}
}
