using System;
using System.IO;
using System.Net.Sockets;
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

			// Two attempts: a long-running prior BKRP attack (or any other lengthy SMB
			// operation against this DC) can leave the DC's half of the cached TCP socket
			// closed while RpcSmbClient still considers the session alive. The first
			// attempt then fails immediately with WSAECONNRESET. We catch that one
			// transport-reset, force-disconnect every cached connection to the DC, and
			// try once more on a guaranteed-fresh connection. If the second attempt also
			// fails it's a real error and we let it propagate.
			for (int attempt = 0; attempt < 2; attempt++)
			{
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

					// [MS-BKRP] §2.1 mandates Kerberos + PacketPrivacy. Unlike winreg/srvsvc which rely on
					// the SMB session context, BKRP requires RPC-level auth so lsass.exe can identify the
					// caller. With RpcAuthLevel.None the server returns ACCESS_DENIED even though the SMB
					// session is authenticated. DC credentials must be configured before calling here.
					var spn = client.GetSpnFor(dcName);
					await this._rpcClient
						.BindProxyToStream(client.Proxy, spn, RpcAuthLevel.PacketPrivacy, stream, cancellationToken)
						.ConfigureAwait(false);

					var result = new BkrpSession(client, share, stream);
					share = null;
					stream = null;
					return result;
				}
				catch (Exception ex) when (attempt == 0 && IsLikelyStaleSmbConnection(ex))
				{
					this.LogVerbose(
						$"OpenBkrpSessionAsync: first attempt against {dcName} failed with " +
						$"transport reset ({ex.GetType().Name}: {ex.Message}). " +
						$"Forcing disconnect and retrying once on a fresh connection.");

					try
					{
						await this.DisconnectServerAsync(dcName, force: true).ConfigureAwait(false);
					}
					catch (Exception disconnectEx)
					{
						this.LogDiagnostic(
							$"OpenBkrpSessionAsync: best-effort disconnect of {dcName} threw " +
							$"{disconnectEx.GetType().Name}: {disconnectEx.Message} (ignored).");
					}
					// Fall through to the next loop iteration for the retry attempt.
				}
				finally
				{
					stream?.Dispose();
					if (pipe != null) await pipe.DisposeAsync().ConfigureAwait(false);
					if (share != null) await share.DisposeAsync().ConfigureAwait(false);
				}
			}

			// Unreachable: attempt 0 either returns or its catch swallows the exception
			// and continues; attempt 1 either returns or its exception propagates because
			// the catch's `when` filter requires attempt == 0.
			throw new InvalidOperationException(
				$"OpenBkrpSessionAsync: exhausted retries opening BKRP session on {dcName}.");
		}

		// Returns true for transport-layer failures that typically indicate the cached
		// SMB session/socket has gone stale (peer RST, half-closed socket, dead session)
		// and a force-disconnect + reconnect is warranted. Walks the inner exception
		// chain because Stream-layer code in the SMB stack tends to wrap SocketException
		// inside IOException.
		private static bool IsLikelyStaleSmbConnection(Exception? ex)
		{
			for (var current = ex; current != null; current = current.InnerException)
			{
				if (current is SocketException se)
				{
					switch (se.SocketErrorCode)
					{
						case SocketError.ConnectionReset:
						case SocketError.ConnectionAborted:
						case SocketError.NotConnected:
						case SocketError.Shutdown:
						case SocketError.NetworkReset:
							return true;
					}
				}

				if (current is ObjectDisposedException)
					return true;
			}
			return false;
		}
	}
}
