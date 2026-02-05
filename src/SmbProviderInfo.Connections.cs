using System.Threading.Tasks;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public partial class SmbProviderInfo
	{
		internal Task DisconnectServerAsync(string serverName, int? port = null, bool force = false)
		{
			this.InvalidateRegistrySessions(serverName, RegistrySessionInvalidationReason.Disconnect);
			return Task.WhenAll(
				this.SmbClient.DisconnectServerAsync(serverName, port, force),
				this.RpcSmbClient.DisconnectServerAsync(serverName, port, force));
		}

		internal Task DisconnectAllAsync(bool force = false)
		{
			this.InvalidateRegistrySessions(null, RegistrySessionInvalidationReason.Disconnect);
			return Task.WhenAll(
				this.SmbClient.DisconnectAllAsync(force),
				this.RpcSmbClient.DisconnectAllAsync(force));
		}
	}
}
