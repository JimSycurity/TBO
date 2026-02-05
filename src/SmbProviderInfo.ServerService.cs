using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Titanis;
using Titanis.DceRpc;
using Titanis.DceRpc.Client;
using Titanis.Msrpc.Mswkst;
using Titanis.Smb2;
using Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class ServerServiceSession : IAsyncDisposable, IDisposable
	{
		internal ServerServiceSession(ServerServiceClient client, Smb2TreeConnect share, Stream stream)
		{
			this.Client = client ?? throw new ArgumentNullException(nameof(client));
			this._share = share ?? throw new ArgumentNullException(nameof(share));
			this._stream = stream ?? throw new ArgumentNullException(nameof(stream));
		}

		public ServerServiceClient Client { get; }

		private readonly Smb2TreeConnect _share;
		private readonly Stream _stream;
		private bool _disposed;

		public async ValueTask DisposeAsync()
		{
			if (this._disposed)
				return;
			this._disposed = true;

			try
			{
				this.Client.Dispose();
			}
			finally
			{
				this._stream.Dispose();
				await this._share.DisposeAsync().ConfigureAwait(false);
			}
		}

		public void Dispose()
		{
			this.DisposeAsync().GetAwaiter().GetResult();
		}
	}

	public partial class SmbProviderInfo
	{
		internal async Task<ServerServiceSession> OpenServerServiceSessionAsync(
			string serverName,
			CancellationToken cancellationToken)
		{
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("Server name must be provided.", nameof(serverName));

			var client = new ServerServiceClient();
			Smb2TreeConnect? share = null;
			Smb2Pipe? pipe = null;
			Stream? stream = null;
			var pipeName = client.WellKnownPipeName ?? ServerServiceClient.PipeName;

			try
			{
				var parms = this.GetConnectParametersFor(serverName, true);
				var port = parms?.RemotePort ?? Smb2Client.TcpPort;
				var session = await this.RpcSmbClient.GetSession(serverName, port, this.RpcSmbClient.DefaultSessionOptions, cancellationToken).ConfigureAwait(false);
				share = await session.OpenTreeAsync(
					new UncPath(serverName, port, Smb2Client.IpcName, null),
					this.RpcSmbClient.DefaultShareOptions.MustEncryptData,
					cancellationToken).ConfigureAwait(false);
				this._log?.WriteDiagnostic($"TBO: Opening {pipeName} pipe on {serverName} (IPC$).");
				pipe = await OpenServerServicePipeAsync(share, pipeName, cancellationToken).ConfigureAwait(false);
				stream = pipe.GetStream(true);
				pipe = null;

				var spn = client.GetSpnFor(share.Session.Connection.ServerName);
				this._log?.WriteDiagnostic($"TBO: Binding srvsvc RPC to {spn}.");
				await this._rpcClient.BindProxyToStream(client.Proxy, spn, RpcAuthLevel.None, stream, cancellationToken).ConfigureAwait(false);

				return new ServerServiceSession(client, share, stream);
			}
			catch
			{
				client.Dispose();
				stream?.Dispose();
				if (pipe != null)
					await pipe.DisposeAsync().ConfigureAwait(false);
				if (share != null)
					await share.DisposeAsync().ConfigureAwait(false);
				throw;
			}
		}

		private async Task<Smb2Pipe> OpenServerServicePipeAsync(
			Smb2TreeConnect share,
			string pipeName,
			CancellationToken cancellationToken)
		{
			if (share is null) throw new ArgumentNullException(nameof(share));
			if (string.IsNullOrWhiteSpace(pipeName))
				throw new ArgumentException("Pipe name must be provided.", nameof(pipeName));

			var candidates = new[]
			{
				pipeName,
				$@"PIPE\{pipeName}"
			};

			const int MaxAttempts = 4;
			TimeSpan delay = TimeSpan.FromMilliseconds(250);
			NtstatusException? last = null;
			for (int attempt = 1; attempt <= MaxAttempts; attempt++)
			{
				foreach (var candidate in candidates)
				{
					try
					{
						return await share.OpenPipeAsync(candidate, cancellationToken).ConfigureAwait(false);
					}
					catch (NtstatusException ex) when (ex.StatusCode is Ntstatus.STATUS_PIPE_NOT_AVAILABLE
						or Ntstatus.STATUS_OBJECT_NAME_NOT_FOUND
						or Ntstatus.STATUS_OBJECT_PATH_NOT_FOUND)
					{
						last = ex;
						this._log?.WriteWarning($"TBO: Pipe '{candidate}' unavailable on {share.Session.Connection.ServerName}: {ex.StatusCode} (attempt {attempt}/{MaxAttempts}).");
					}
				}

				if (attempt < MaxAttempts)
				{
					this._log?.WriteDiagnostic($"TBO: Retry opening {pipeName} pipe in {delay.TotalMilliseconds:0} ms.");
					await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
					delay = TimeSpan.FromMilliseconds(Math.Min(delay.TotalMilliseconds * 2, 2000));
				}
			}

			if (last != null)
				throw last;

			throw new InvalidOperationException($"Unable to open pipe '{pipeName}' on {share.Session.Connection.ServerName}.");
		}
	}
}
