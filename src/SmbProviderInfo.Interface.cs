using System;
using System.Threading;
using System.Threading.Tasks;
using Titanis.Smb2;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public partial class SmbProviderInfo : ISmbProviderInfo
	{
		Smb2Client ISmbProviderInfo.SmbClient => this.SmbClient;

		object? ISmbProviderInfo.DefaultConnectParameters
		{
			get => this.DefaultConnectParameters;
			set
			{
				if (value is null)
					throw new ArgumentNullException(nameof(value));
				if (value is not SmbConnectionParameters parameters)
					throw new ArgumentException("DefaultConnectParameters must be a SmbConnectionParameters instance.", nameof(value));
				this.DefaultConnectParameters = parameters;
			}
		}

		object? ISmbProviderInfo.GetConnectParametersFor(string serverName, bool defaultIfNone)
			=> this.GetConnectParametersFor(serverName, defaultIfNone);

		void ISmbProviderInfo.SetConnectParameters(string serverName, object parameters)
		{
			if (parameters is not SmbConnectionParameters connectionParameters)
				throw new ArgumentException("SetConnectParameters expects a SmbConnectionParameters instance.", nameof(parameters));
			this.SetConnectParameters(serverName, connectionParameters);
		}

		Task<ServerServiceSession> ISmbProviderInfo.OpenServerServiceSessionAsync(string serverName, CancellationToken cancellationToken)
			=> this.OpenServerServiceSessionAsync(serverName, cancellationToken);

		Task<RemoteRegistrySession> ISmbProviderInfo.OpenRemoteRegistrySessionAsync(string serverName, CancellationToken cancellationToken)
			=> this.OpenRemoteRegistrySessionAsync(serverName, cancellationToken);

		Task ISmbProviderInfo.DisconnectServerAsync(string serverName, int? port, bool force)
			=> this.DisconnectServerAsync(serverName, port, force);

		Task ISmbProviderInfo.DisconnectAllAsync(bool force)
			=> this.DisconnectAllAsync(force);

		void ISmbProviderInfo.LogException(string context, Exception ex)
			=> this.LogException(context, ex);
	}
}
