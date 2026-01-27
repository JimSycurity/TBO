using System.Threading.Tasks;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public partial class SmbProviderInfo
	{
		internal Task DisconnectServerAsync(string serverName, int? port = null)
		{
			return Task.WhenAll(
				this.SmbClient.DisconnectServerAsync(serverName, port),
				this.RpcSmbClient.DisconnectServerAsync(serverName, port));
		}

		internal Task DisconnectAllAsync()
		{
			return Task.WhenAll(
				this.SmbClient.DisconnectAllAsync(),
				this.RpcSmbClient.DisconnectAllAsync());
		}
	}
}
