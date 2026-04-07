using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Titanis.DceRpc;
using Titanis.DceRpc.Client;
using Titanis.Net;
using Titanis.Smb2;
using Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public partial class SmbProviderInfo
	{
		// Opens an authenticated BKRP session to a domain controller.
		//
		// [MS-BKRP] § 2.1 mandates Kerberos + PacketPrivacy authentication.
		// The DC is a separate host from the target machine — the caller must
		// supply the DC address explicitly.
		internal async Task<BkrpSession> OpenBkrpSessionAsync(
			string dcName,
			CancellationToken cancellationToken)
		{
			if (string.IsNullOrWhiteSpace(dcName))
				throw new ArgumentException("Domain controller name must be provided.", nameof(dcName));

			var client = new BkrpClient();
			Smb2TreeConnect? share = null;
			Smb2Pipe? pipe = null;
			Stream? stream = null;

			try
			{
				var parms = this.GetConnectParametersFor(dcName, defaultIfNone: true);
				var port = (parms as SmbConnectionParameters)?.RemotePort ?? Smb2Client.TcpPort;

				var session = await this.RpcSmbClient
					.GetSession(dcName, port, this.RpcSmbClient.DefaultSessionOptions, cancellationToken)
					.ConfigureAwait(false);

				share = await session.OpenTreeAsync(
					new UncPath(dcName, port, Smb2Client.IpcName, null),
					this.RpcSmbClient.DefaultShareOptions.MustEncryptData,
					cancellationToken).ConfigureAwait(false);

				int retries = 3;
				while (retries-- > 0)
				{
					try
					{
						pipe = await share.OpenPipeAsync(BkrpClient.BkrpPipeName, cancellationToken)
							.ConfigureAwait(false);
						break;
					}
					catch (NtstatusException ex) when (ex.StatusCode == Ntstatus.STATUS_PIPE_NOT_AVAILABLE)
					{
						await Task.Delay(100, cancellationToken).ConfigureAwait(false);
					}
				}

				if (pipe == null)
					throw new InvalidOperationException(
						$"Could not open \\PIPE\\{BkrpClient.BkrpPipeName} on {dcName} after retries.");

				stream = pipe.GetStream(true);
				pipe = null;

				// MS-BKRP requires PacketPrivacy (full encryption).
				var spn = client.GetSpnFor(dcName);
				await this._rpcClient
					.BindProxyToStream(client.Proxy, spn, RpcAuthLevel.PacketPrivacy, stream, cancellationToken)
					.ConfigureAwait(false);

				var result = new BkrpSession(client, share, stream);
				share = null;
				stream = null;
				return result;
			}
			finally
			{
				stream?.Dispose();
				if (pipe != null) await pipe.DisposeAsync().ConfigureAwait(false);
				if (share != null) await share.DisposeAsync().ConfigureAwait(false);
			}
		}
	}
}
