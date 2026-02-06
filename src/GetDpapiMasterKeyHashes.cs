using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Management.Automation;
using System.Threading;
using Titanis.Net;
using Titanis.Smb2;
using Titanis.Winterop;
using Titanis.Winterop.Security;
using Winterop = Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboDpapiMasterKeyHashInfo
	{
		public string ServerName { get; init; } = string.Empty;
		public string Scope { get; init; } = string.Empty;
		public string? UserSid { get; init; }
		public string KeyPath { get; init; } = string.Empty;
		public string? MasterKeyGuid { get; init; }
		public bool IsPreferred { get; init; }
		public bool? IsDomain { get; init; }
		public int HashContext { get; init; }
		public string? Hash { get; init; }
		public string? HashLine { get; init; }
		public string? FailureReason { get; init; }
	}

	[Cmdlet(VerbsCommon.Get, "TBODpapiMasterKeyHashes")]
	[OutputType(typeof(TboDpapiMasterKeyHashInfo))]
	public sealed class GetTBODpapiMasterKeyHashes : SmbCmdlet
	{
		[Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true)]
		public string ServerName { get; set; } = string.Empty;

		// This is primarily intended for user-scoped master keys (password cracking), but Scope is kept for parity.
		[Parameter]
		public DpapiMasterKeyScope Scope { get; set; } = DpapiMasterKeyScope.User;

		[Parameter]
		public string ShareName { get; set; } = DpapiMasterKeyLocator.DefaultShareName;

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

			if (this.Scope == DpapiMasterKeyScope.None)
				return;

			var domainCache = new Dictionary<string, bool?>(StringComparer.OrdinalIgnoreCase);

			bool? TryGetIsDomainDir(string directoryPath, out string? failure)
			{
				failure = null;
				if (string.IsNullOrWhiteSpace(directoryPath))
				{
					failure = "Directory path was empty.";
					return null;
				}

				if (domainCache.TryGetValue(directoryPath, out var cached))
					return cached;

				var fileSystem = SmbFileSystemResolver.Resolve(smb);
				ISmbDirectory? dir = null;
				try
				{
					dir = fileSystem.OpenDirectory(UncPath.Parse(directoryPath), cancellationToken);
					foreach (var entry in dir.QueryEntries("*", Smb2Directory.Smb2DirQueryOptions.None, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken))
					{
						if (string.IsNullOrEmpty(entry.FileName))
							continue;
						if (entry.FileName is "." or "..")
							continue;

						bool isDirectory = (entry.FileAttributes & Winterop.FileAttributes.Directory) != 0;
						if (isDirectory)
							continue;

						if (entry.FileName.StartsWith("BK-", StringComparison.OrdinalIgnoreCase))
						{
							domainCache[directoryPath] = true;
							return true;
						}
					}

					domainCache[directoryPath] = false;
					return false;
				}
				catch (NtstatusException ex) when (IsMissingPath(ex))
				{
					failure = $"Directory not found: {ex.StatusCode}.";
					domainCache[directoryPath] = null;
					return null;
				}
				catch (NtstatusException ex) when (IsAccessDenied(ex))
				{
					failure = $"Access denied: {ex.StatusCode}.";
					domainCache[directoryPath] = null;
					return null;
				}
				catch (Win32Exception ex)
				{
					failure = ex.Message;
					domainCache[directoryPath] = null;
					return null;
				}
				catch (Exception ex)
				{
					smb.LogException($"Get-TBODpapiMasterKeyHashes failed to enumerate {directoryPath} for BK-* detection", ex);
					failure = ex.Message;
					domainCache[directoryPath] = null;
					return null;
				}
				finally
				{
					if (dir != null)
						dir.Dispose();
				}
			}

			var locations = DpapiMasterKeyLocator.Enumerate(
				smb,
				serverName,
				shareName,
				this.Scope,
				message => this.WriteWarning(message),
				null,
				message => this.WriteVerbose(message),
				cancellationToken);

			foreach (var location in locations)
			{
				if (string.IsNullOrWhiteSpace(location.UserSid))
				{
					this.WriteObject(new TboDpapiMasterKeyHashInfo
					{
						ServerName = this.ServerName,
						Scope = location.Scope,
						UserSid = location.UserSid,
						KeyPath = location.KeyPath,
						MasterKeyGuid = location.MasterKeyGuid,
						IsPreferred = location.IsPreferred,
						HashContext = 0,
						FailureReason = "UserSid was missing; cannot format master key hash."
					});
					continue;
				}

				var keyDir = Path.GetDirectoryName(location.KeyPath);
				bool? isDomain = null;
				int context = 3;

				if (location.Scope.Equals("User", StringComparison.OrdinalIgnoreCase))
				{
					var detected = TryGetIsDomainDir(keyDir ?? string.Empty, out var domainDetectFailure);
					isDomain = detected;

					if (detected.HasValue)
					{
						context = detected.Value ? 3 : 1;
					}
					else
					{
						context = 3;
						if (!string.IsNullOrWhiteSpace(domainDetectFailure))
						{
							this.WriteVerbose($"Get-TBODpapiMasterKeyHashes could not determine domain/local context for {location.KeyPath}: {domainDetectFailure} Defaulting context to 3.");
						}
					}
				}
				else
				{
					context = 1;
				}

				byte[]? rawFile = null;
				try
				{
					rawFile = DpapiHelpers.ReadFileBytes(smb, UncPath.Parse(location.KeyPath), cancellationToken);
				}
				catch (Exception ex)
				{
					this.LogException(smb, $"Get-TBODpapiMasterKeyHashes failed to read {location.KeyPath}", ex, emitWarning: false);
					this.WriteObject(new TboDpapiMasterKeyHashInfo
					{
						ServerName = this.ServerName,
						Scope = location.Scope,
						UserSid = location.UserSid,
						KeyPath = location.KeyPath,
						MasterKeyGuid = location.MasterKeyGuid,
						IsPreferred = location.IsPreferred,
						IsDomain = isDomain,
						HashContext = context,
						FailureReason = $"Failed to read master key file: {ex.Message}"
					});
					continue;
				}

				DpapiMasterKeyFile? masterKeyFile = null;
				try
				{
					masterKeyFile = DpapiMasterKeyCrypto.ParseMasterKeyFile(rawFile);
				}
				catch (Exception ex)
				{
					this.LogException(smb, $"Get-TBODpapiMasterKeyHashes failed to parse {location.KeyPath}", ex, emitWarning: false);
					this.WriteObject(new TboDpapiMasterKeyHashInfo
					{
						ServerName = this.ServerName,
						Scope = location.Scope,
						UserSid = location.UserSid,
						KeyPath = location.KeyPath,
						MasterKeyGuid = location.MasterKeyGuid,
						IsPreferred = location.IsPreferred,
						IsDomain = isDomain,
						HashContext = context,
						FailureReason = $"Failed to parse master key file: {ex.Message}"
					});
					continue;
				}

				var parsedGuid = masterKeyFile.Guid?.ToString();
				var parsedGuidText = parsedGuid ?? masterKeyFile.GuidText?.Trim().Trim('{', '}');
				var masterKeyGuid = string.IsNullOrWhiteSpace(parsedGuidText)
					? location.MasterKeyGuid
					: parsedGuidText;

				if (!string.IsNullOrWhiteSpace(masterKeyGuid)
					&& !string.IsNullOrWhiteSpace(location.MasterKeyGuid)
					&& !string.Equals(masterKeyGuid, location.MasterKeyGuid, StringComparison.OrdinalIgnoreCase))
				{
					this.WriteVerbose($"Get-TBODpapiMasterKeyHashes detected header GUID {masterKeyGuid} for {location.KeyPath} (path GUID {location.MasterKeyGuid}).");
				}

				if (!DpapiMasterKeyHashFormatter.TryFormatDpapiMkHash(masterKeyFile, location.UserSid, context, out var guidWithBraces, out var hashText, out var formatFailure))
				{
					this.WriteObject(new TboDpapiMasterKeyHashInfo
					{
						ServerName = this.ServerName,
						Scope = location.Scope,
						UserSid = location.UserSid,
						KeyPath = location.KeyPath,
						MasterKeyGuid = masterKeyGuid,
						IsPreferred = location.IsPreferred,
						IsDomain = isDomain,
						HashContext = context,
						FailureReason = formatFailure
					});
					continue;
				}

				this.WriteObject(new TboDpapiMasterKeyHashInfo
				{
					ServerName = this.ServerName,
					Scope = location.Scope,
					UserSid = location.UserSid,
					KeyPath = location.KeyPath,
					MasterKeyGuid = masterKeyGuid,
					IsPreferred = location.IsPreferred,
					IsDomain = isDomain,
					HashContext = context,
					Hash = hashText,
					HashLine = $"{guidWithBraces}:{hashText}"
				});
			}
		}

		protected override void StopProcessing()
		{
			this._cancelSource?.Cancel();
			base.StopProcessing();
		}

		private static bool IsMissingPath(NtstatusException ex)
		{
			return ex.StatusCode is Ntstatus.STATUS_OBJECT_NAME_NOT_FOUND
				or Ntstatus.STATUS_OBJECT_PATH_NOT_FOUND
				or Ntstatus.STATUS_OBJECT_NAME_INVALID;
		}

		private static bool IsAccessDenied(NtstatusException ex)
		{
			return ex.StatusCode is Ntstatus.STATUS_ACCESS_DENIED
				or Ntstatus.STATUS_PRIVILEGE_NOT_HELD;
		}
	}
}

