using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Titanis.Net;
using Titanis.Smb2;
using Titanis.Winterop;
using Titanis.Winterop.Security;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public partial class SmbProviderInfo
	{
		private sealed class BackupIntentProbeResult
		{
			public BackupIntentProbeResult(bool available, string? errorMessage)
			{
				this.Available = available;
				this.ErrorMessage = errorMessage;
			}

			public bool Available { get; }
			public string? ErrorMessage { get; }
		}

		private static readonly TimeSpan BackupIntentProbeTimeout = TimeSpan.FromSeconds(10);
		private readonly Dictionary<string, BackupIntentProbeResult> _backupIntentProbe = new(StringComparer.OrdinalIgnoreCase);

		internal Task EnsureBackupIntentAccessAsync(UncPath sharePath, Smb2TreeConnect? share, CancellationToken cancellationToken)
		{
			if ((this.SmbClient.RequiredCreateOptions & Smb2FileCreateOptions.OpenForBackupIntent) == 0)
				return Task.CompletedTask;

			if (string.IsNullOrWhiteSpace(sharePath?.ServerName))
				return Task.CompletedTask;

			var key = $"{sharePath.ServerName}:{sharePath.Port}";
			lock (this._backupIntentProbe)
			{
				if (this._backupIntentProbe.TryGetValue(key, out var cached))
				{
					if (!cached.Available)
						throw new InvalidOperationException(cached.ErrorMessage ?? $"Backup intent is not available on {sharePath.ServerName}.");
					return Task.CompletedTask;
				}
			}

			return EnsureBackupIntentAccessCoreAsync(sharePath, share, key, cancellationToken);
		}

		private async Task EnsureBackupIntentAccessCoreAsync(
			UncPath sharePath,
			Smb2TreeConnect? share,
			string cacheKey,
			CancellationToken cancellationToken)
		{
			this._log?.WriteDiagnostic($"TBO: Probing backup intent access on {sharePath.ServerName}.");
			using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			var timeoutToken = timeoutCts.Token;

			try
			{
				var probeTask = ProbeBackupIntentAccessAsync(sharePath, share, timeoutToken);
				var timeoutTask = Task.Delay(BackupIntentProbeTimeout, cancellationToken);
				var completed = await Task.WhenAny(probeTask, timeoutTask).ConfigureAwait(false);

				if (completed == timeoutTask)
				{
					timeoutCts.Cancel();
					await this.DisconnectServerAsync(sharePath.ServerName, sharePath.Port, true).ConfigureAwait(false);
					var message = $"Timed out verifying backup intent access on {sharePath.ServerName}. " +
						"SeBackupPrivilege/SeRestorePrivilege may be missing. Update rights assignments and reconnect.";
					CacheBackupIntentFailure(cacheKey, message);
					this._log?.WriteWarning($"TBO: {message}");
					throw new InvalidOperationException(message);
				}

				await probeTask.ConfigureAwait(false);

				lock (this._backupIntentProbe)
				{
					this._backupIntentProbe[cacheKey] = new BackupIntentProbeResult(true, null);
				}
				this._log?.WriteDiagnostic($"TBO: Backup intent probe succeeded on {sharePath.ServerName}.");
			}
			catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested || cancellationToken.IsCancellationRequested)
			{
				var message = $"Timed out verifying backup intent access on {sharePath.ServerName}. " +
					"SeBackupPrivilege/SeRestorePrivilege may be missing. Update rights assignments and reconnect.";
				CacheBackupIntentFailure(cacheKey, message);
				this._log?.WriteWarning($"TBO: {message}");
				throw new InvalidOperationException(message);
			}
			catch (NtstatusException ex) when (ex.StatusCode is Ntstatus.STATUS_PRIVILEGE_NOT_HELD
				or Ntstatus.STATUS_ACCESS_DENIED)
			{
				var message = $"Backup intent is not permitted for the current account on {sharePath.ServerName}. " +
					"SeBackupPrivilege/SeRestorePrivilege may be missing or removed by GPO. " +
					"Update rights assignments and reconnect.";
				CacheBackupIntentFailure(cacheKey, message);
				this._log?.WriteWarning($"TBO: {message}");
				throw new InvalidOperationException(message, ex);
			}
			catch (Exception ex)
			{
				var message = $"Failed to verify backup intent access on {sharePath.ServerName}: {ex.Message}";
				CacheBackupIntentFailure(cacheKey, message);
				this._log?.WriteWarning($"TBO: {message}");
				throw new InvalidOperationException(message, ex);
			}
		}

		private async Task ProbeBackupIntentAccessAsync(UncPath sharePath, Smb2TreeConnect? share, CancellationToken cancellationToken)
		{
			var shareToUse = share ?? await this.SmbClient.GetShare(sharePath.GetShare(), cancellationToken).ConfigureAwait(false);
			await using var dir = await shareToUse.OpenDirectoryAsync(string.Empty, cancellationToken).ConfigureAwait(false);
			await dir.QueryDirAsync(
				"*",
				Smb2Directory.Smb2DirQueryOptions.None,
				SecurityInfo.None,
				Smb2Directory.DefaultQueryBufferSize,
				cancellationToken).ConfigureAwait(false);
		}

		private void CacheBackupIntentFailure(string cacheKey, string message)
		{
			lock (this._backupIntentProbe)
			{
				this._backupIntentProbe[cacheKey] = new BackupIntentProbeResult(false, message);
			}
		}
	}
}
