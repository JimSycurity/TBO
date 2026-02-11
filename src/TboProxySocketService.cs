using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Titanis.Net;
using Titanis.Socks;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal sealed class TboProxySocketService : ISocketService
	{
		private readonly SmbProviderInfo _provider;
		private readonly ISocketService _directSocketService;

		private readonly ConcurrentDictionary<string, EndPoint> _proxyEndPoints =
			new(StringComparer.OrdinalIgnoreCase);

		private readonly ConcurrentDictionary<string, Socks5Client> _socksClients =
			new(StringComparer.OrdinalIgnoreCase);

		internal TboProxySocketService(SmbProviderInfo provider, ISocketService directSocketService)
		{
			this._provider = provider ?? throw new ArgumentNullException(nameof(provider));
			this._directSocketService = directSocketService ?? throw new ArgumentNullException(nameof(directSocketService));
		}

		public ISocket CreateSocket(AddressFamily addressFamily, SocketType socketType, ProtocolType protocolType)
			=> this._directSocketService.CreateSocket(addressFamily, socketType, protocolType);

		public Task<ISocket> ConnectTcp(EndPoint remoteEP, CancellationToken cancellationToken)
		{
			ArgumentNullException.ThrowIfNull(remoteEP);

			if (!TryResolveProxy(remoteEP, out var proxySetting, out var serverName))
				return this._directSocketService.ConnectTcp(remoteEP, cancellationToken);

			EndPoint proxyEP;
			try
			{
				proxyEP = this._proxyEndPoints.GetOrAdd(proxySetting, ParseSocks5ProxyEndPoint);
			}
			catch (Exception ex) when (ex is ArgumentException or NotSupportedException)
			{
				throw new InvalidOperationException(
					$"Invalid SOCKS5 proxy setting '{proxySetting}'. Expected host:port or socks5://host:port. SOCKS5 authentication is not supported.",
					ex);
			}

			var socksClient = this._socksClients.GetOrAdd(
				proxySetting,
				_ => new Socks5Client(proxyEP, underlyingSocketService: PlatformSocketService.Shared));

			var proxiedRemoteEP = RewriteRemoteEndpointForProxy(remoteEP, serverName);
			return socksClient.ConnectTcp(proxiedRemoteEP, cancellationToken);
		}

		private bool TryResolveProxy(EndPoint remoteEP, out string proxySetting, out string? serverName)
		{
			proxySetting = string.Empty;
			serverName = null;

			if (remoteEP is DnsEndPoint dnsEP)
				serverName = dnsEP.Host;

			var parms = serverName != null
				? SmbConnectionParameters.ResolveOrDefault(this._provider, serverName)
				: SmbConnectionParameters.ResolveDefault(this._provider.DefaultConnectParameters);

			if (!TryNormalizeProxySetting(parms.Socks5Proxy, out var normalized))
				return false;

			proxySetting = normalized;
			return true;
		}

		private static bool TryNormalizeProxySetting(string? value, out string normalized)
		{
			normalized = string.Empty;
			if (string.IsNullOrWhiteSpace(value))
				return false;

			var v = value.Trim();
			if (v.Equals("none", StringComparison.OrdinalIgnoreCase)
				|| v.Equals("off", StringComparison.OrdinalIgnoreCase)
				|| v.Equals("direct", StringComparison.OrdinalIgnoreCase)
				|| v.Equals("false", StringComparison.OrdinalIgnoreCase)
				|| v.Equals("0", StringComparison.OrdinalIgnoreCase))
			{
				return false;
			}

			normalized = v;
			return true;
		}

		private EndPoint RewriteRemoteEndpointForProxy(EndPoint originalRemoteEP, string? serverName)
		{
			if (serverName == null || originalRemoteEP is not DnsEndPoint dnsEP)
				return originalRemoteEP;

			// PlatformSocketService normally resolves DnsEndPoint using the provider's INameResolverService,
			// which applies per-server HostName overrides. SOCKS5 bypasses local resolution by design, so
			// apply the same HostName mapping before handing the target host to the proxy.
			var parms = SmbConnectionParameters.TryGetServerSpecific(this._provider, serverName);
			var targetHost = !string.IsNullOrWhiteSpace(parms?.HostName) ? parms.HostName! : serverName;
			return CreateHostEndPoint(targetHost, dnsEP.Port);
		}

		private const int DefaultSocks5Port = 1080;

		private static EndPoint ParseSocks5ProxyEndPoint(string value)
		{
			if (string.IsNullOrWhiteSpace(value))
				throw new ArgumentException("Proxy setting is empty.", nameof(value));

			value = value.Trim();

			if (value.Contains("://", StringComparison.Ordinal))
				return ParseSocks5ProxyUri(value);

			var (host, port) = ParseHostPort(value, defaultPort: DefaultSocks5Port);
			return CreateHostEndPoint(host, port);
		}

		private static EndPoint ParseSocks5ProxyUri(string value)
		{
			if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
				throw new ArgumentException("Proxy URI is invalid.", nameof(value));

			if (!uri.Scheme.Equals("socks5", StringComparison.OrdinalIgnoreCase)
				&& !uri.Scheme.Equals("socks", StringComparison.OrdinalIgnoreCase))
			{
				throw new ArgumentException($"Unsupported proxy scheme '{uri.Scheme}'.", nameof(value));
			}

			if (!string.IsNullOrEmpty(uri.UserInfo))
				throw new NotSupportedException("SOCKS5 proxy authentication is not supported.");

			var host = uri.Host;
			if (string.IsNullOrWhiteSpace(host))
				throw new ArgumentException("Proxy URI must include a host.", nameof(value));

			var port = uri.Port > 0 ? uri.Port : DefaultSocks5Port;
			return CreateHostEndPoint(host, port);
		}

		private static (string host, int port) ParseHostPort(string value, int defaultPort)
		{
			if (string.IsNullOrWhiteSpace(value))
				throw new ArgumentException("Proxy host value is empty.", nameof(value));

			value = value.Trim();

			if (value.StartsWith('['))
			{
				int close = value.IndexOf(']');
				if (close < 0)
					throw new ArgumentException("Invalid IPv6 proxy format. Use [::1]:1080.", nameof(value));

				var host = value.Substring(1, close - 1);
				if (string.IsNullOrWhiteSpace(host))
					throw new ArgumentException("IPv6 proxy host is empty.", nameof(value));

				if (close == value.Length - 1)
					return (host, defaultPort);

				if (value[close + 1] != ':')
					throw new ArgumentException("Invalid IPv6 proxy format. Use [::1]:1080.", nameof(value));

				var portPart = value.Substring(close + 2);
				if (!TryParsePort(portPart, out int port))
					throw new ArgumentException($"Invalid proxy port '{portPart}'.", nameof(value));

				return (host, port);
			}

			// Unbracketed IPv6 without an explicit port.
			if (IPAddress.TryParse(value, out _))
				return (value, defaultPort);

			int firstColon = value.IndexOf(':');
			if (firstColon < 0)
				return (value, defaultPort);

			int lastColon = value.LastIndexOf(':');
			if (firstColon != lastColon)
			{
				throw new ArgumentException(
					"Invalid proxy format. If using IPv6, wrap the address in brackets: [::1]:1080.",
					nameof(value));
			}

			var hostPart = value.Substring(0, lastColon);
			var portPart2 = value.Substring(lastColon + 1);
			if (string.IsNullOrWhiteSpace(hostPart))
				throw new ArgumentException("Proxy host is empty.", nameof(value));

			if (!TryParsePort(portPart2, out int port2))
				throw new ArgumentException($"Invalid proxy port '{portPart2}'.", nameof(value));

			return (hostPart, port2);
		}

		private static bool TryParsePort(string value, out int port)
		{
			port = 0;
			if (!int.TryParse(value, out port))
				return false;
			return port is > 0 and <= 65535;
		}

		private static EndPoint CreateHostEndPoint(string host, int port)
		{
			if (IPAddress.TryParse(host, out var ip))
				return new IPEndPoint(ip, port);

			return new DnsEndPoint(host, port);
		}
	}
}

