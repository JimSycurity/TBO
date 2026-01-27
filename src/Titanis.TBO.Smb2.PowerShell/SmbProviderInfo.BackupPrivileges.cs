using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Titanis;
using Titanis.DceRpc;
using Titanis.DceRpc.Client;
using Titanis.Msrpc.Mslsar;
using Titanis.Security;
using Titanis.Smb2;
using Titanis.Winterop.Security;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public partial class SmbProviderInfo
	{
		private static readonly TimeSpan LsaPrivilegeCheckTimeout = TimeSpan.FromSeconds(30);
		private readonly RpcClient _rpcClient;
		private readonly HashSet<string> _autoGrantAttempts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

		void ISmb2TraceCallback.OnConnecting(System.Net.EndPoint serverEP, string serverName, Smb2ConnectionOptions options)
		{
		}

		void ISmb2TraceCallback.OnConnected(System.Net.EndPoint serverEP, Smb2Connection connection)
		{
		}

		void ISmb2TraceCallback.OnSessionAuthenticated(Smb2Session session)
		{
			// LSA privilege checks require admin rights on the remote host; skip them for Backup Operators.
		}

		void ISmb2TraceCallback.OnShareConnected(UncPath uncPath, Smb2TreeConnect share)
		{
		}

		void ISmb2TraceCallback.OnDfsReferralReceived(UncPath uncPath, DfsReferral referral)
		{
		}

		void ISmb2TraceCallback.OnDfsReferralConnectFailed(UncPath uncPath, DfsReferral referral, DfsReferralEntry entry, UncPath referredPath, Exception ex)
		{
		}

		void ISmb2TraceCallback.OnDfsReferralFollowed(UncPath originalPath, Smb2TreeConnect referredShare, UncPath referredPath)
		{
		}

		private async Task EnsureBackupPrivilegesAsync(Smb2Session session, CancellationToken cancellationToken)
		{
			if (session is null) throw new ArgumentNullException(nameof(session));

			var serverName = session.Connection.ServerName;
			System.Diagnostics.Trace.TraceInformation($"TBO: Checking backup privileges on {serverName}.");

			using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			timeoutCts.CancelAfter(LsaPrivilegeCheckTimeout);
			var timeoutToken = timeoutCts.Token;

			try
			{
				using var lsaClient = new LsaClient();
				await this.BindRpcServiceToPipeAsync(lsaClient, session, LsaClient.LsaPipeName, timeoutToken).ConfigureAwait(false);
				System.Diagnostics.Trace.TraceInformation($"TBO: LSA RPC bound to {serverName}.");

				UserPrincipalName user = await lsaClient.WhoAmI(timeoutToken).ConfigureAwait(false);
				string accountName = FormatAccountName(user);
				System.Diagnostics.Trace.TraceInformation($"TBO: LSA WhoAmI returned {accountName} on {serverName}.");

				using var policy = await lsaClient.OpenPolicy(LsaPolicyAccess.LookupNames | LsaPolicyAccess.ViewLocalInfo, timeoutToken).ConfigureAwait(false);
				var mapping = await policy.ResolveAccountName(accountName, timeoutToken).ConfigureAwait(false);
				if (mapping.AccountSid is null)
					throw new InvalidOperationException($"Unable to resolve account SID for {accountName} on {serverName}.");

				using var account = await policy.OpenAccount(mapping.AccountSid, LsaAccountAccess.View, timeoutToken).ConfigureAwait(false);
				var privileges = await account.GetPrivileges(timeoutToken).ConfigureAwait(false);

				List<string> missing = new List<string>(2);
				bool needsBackup = !privileges.Any(priv => priv.Privilege == Privilege.SeBackupPrivilege);
				bool needsRestore = !privileges.Any(priv => priv.Privilege == Privilege.SeRestorePrivilege);
				if (needsBackup)
					missing.Add(nameof(Privilege.SeBackupPrivilege));
				if (needsRestore)
					missing.Add(nameof(Privilege.SeRestorePrivilege));

				if (missing.Count > 0)
				{
					if (!this.TryMarkAutoGrantAttempt(serverName, accountName))
					{
						throw new InvalidOperationException(
							$"Remote account {accountName} on {serverName} is missing required privileges after auto-grant: {string.Join(", ", missing)}. " +
							"Verify rights assignment and reconnect."
						);
					}

					System.Diagnostics.Trace.TraceWarning($"TBO: Auto-granting {string.Join(", ", missing)} to {accountName} on {serverName}.");
					await this.GrantBackupPrivilegesAsync(lsaClient, mapping.AccountSid, needsBackup, needsRestore, timeoutToken).ConfigureAwait(false);
					session.RequiresReauth = true;
					return;
				}
				System.Diagnostics.Trace.TraceInformation($"TBO: Backup privileges verified on {serverName} for {accountName}.");
			}
			catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
			{
				throw new InvalidOperationException($"Timed out verifying backup privileges on {serverName} after {LsaPrivilegeCheckTimeout.TotalSeconds:0} seconds.");
			}
			catch (Exception ex) when (ex is not InvalidOperationException)
			{
				throw new InvalidOperationException($"Failed to verify backup privileges on {serverName}: {ex.Message}", ex);
			}
		}

		private async Task BindRpcServiceToPipeAsync(
			RpcServiceClient service,
			Smb2Session session,
			string pipeName,
			CancellationToken cancellationToken)
		{
			if (service is null) throw new ArgumentNullException(nameof(service));
			if (session is null) throw new ArgumentNullException(nameof(session));
			if (string.IsNullOrEmpty(pipeName)) throw new ArgumentException($"'{nameof(pipeName)}' cannot be null or empty.", nameof(pipeName));
			if (service.IsBound)
				throw new ArgumentException(@"The service client is already bound and cannot be bound again.", nameof(service));

			Smb2TreeConnect? share = null;
			Smb2Pipe? pipe = null;
			try
			{
				share = await session.OpenTreeAsync(new UncPath(session.Connection.ServerName, Smb2Client.IpcName, null), false, cancellationToken).ConfigureAwait(false);
				pipe = await share.OpenPipeAsync(pipeName, cancellationToken).ConfigureAwait(false);
				var stream = pipe.GetStream(true);
				try
				{
					var spn = service.GetSpnFor(session.Connection.ServerName);
					await this._rpcClient.BindProxyToStream(service.Proxy, spn, RpcAuthLevel.ConfiguredDefault, stream, cancellationToken).ConfigureAwait(false);
					stream = null;
				}
				finally
				{
					stream?.Dispose();
				}
			}
			finally
			{
				if (pipe != null)
					await pipe.DisposeAsync().ConfigureAwait(false);
				if (share != null)
					await share.DisposeAsync().ConfigureAwait(false);
			}
		}

		private static string FormatAccountName(UserPrincipalName user)
		{
			if (user is null) throw new ArgumentNullException(nameof(user));

			if (string.IsNullOrEmpty(user.Realm))
				return user.UserName;

			return $"{user.Realm}\\{user.UserName}";
		}

		private bool TryMarkAutoGrantAttempt(string serverName, string accountName)
		{
			var key = $"{serverName}\\{accountName}";
			lock (this._autoGrantAttempts)
			{
				return this._autoGrantAttempts.Add(key);
			}
		}

		private async Task GrantBackupPrivilegesAsync(
			LsaClient lsaClient,
			SecurityIdentifier accountSid,
			bool needsBackup,
			bool needsRestore,
			CancellationToken cancellationToken)
		{
			if (lsaClient is null) throw new ArgumentNullException(nameof(lsaClient));
			if (!needsBackup && !needsRestore)
				return;

			using var policy = await lsaClient.OpenPolicy(LsaPolicyAccess.LookupNames | LsaPolicyAccess.CreateAccount, cancellationToken).ConfigureAwait(false);
			using var account = await OpenOrCreateAccountForPrivilegeUpdateAsync(policy, accountSid, cancellationToken).ConfigureAwait(false);

			List<PrivilegeInfo> privileges = new List<PrivilegeInfo>(2);
			const PrivilegeAttributes attrs = PrivilegeAttributes.Enabled | PrivilegeAttributes.EnabledByDefault;

			if (needsBackup)
				privileges.Add(new PrivilegeInfo(Privilege.SeBackupPrivilege, attrs));
			if (needsRestore)
				privileges.Add(new PrivilegeInfo(Privilege.SeRestorePrivilege, attrs));

			await account.AddPrivileges(privileges, cancellationToken).ConfigureAwait(false);
		}

		private static async Task<LsaAccount> OpenOrCreateAccountForPrivilegeUpdateAsync(
			LsaPolicy policy,
			SecurityIdentifier accountSid,
			CancellationToken cancellationToken)
		{
			try
			{
				return await policy.OpenAccount(accountSid, LsaAccountAccess.View | LsaAccountAccess.AdjustPrivileges, cancellationToken).ConfigureAwait(false);
			}
			catch (Exception openEx)
			{
				try
				{
					return await policy.CreateAccount(accountSid, LsaAccountAccess.View | LsaAccountAccess.AdjustPrivileges, cancellationToken).ConfigureAwait(false);
				}
				catch (Exception createEx)
				{
					throw new InvalidOperationException($"Unable to open or create the LSA account for {accountSid}: {openEx.Message}", createEx);
				}
			}
		}
	}
}
