using System;
using System.Threading;
using System.Threading.Tasks;
using Titanis.Smb2;

namespace Titanis.Tbo.Smb2.PowerShell
{
public interface ISmbProviderInfo
{
	Smb2Client SmbClient { get; }
	object? DefaultConnectParameters { get; set; }
	object? GetConnectParametersFor(string serverName, bool defaultIfNone);
	void SetConnectParameters(string serverName, object parameters);
		Task<ServerServiceSession> OpenServerServiceSessionAsync(string serverName, CancellationToken cancellationToken);
		Task<RemoteRegistrySession> OpenRemoteRegistrySessionAsync(string serverName, CancellationToken cancellationToken);
		Task DisconnectServerAsync(string serverName, int? port = null);
		Task DisconnectAllAsync();
		void LogException(string context, Exception ex);
	}
}
