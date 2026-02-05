using System;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public enum RegistryRetryPolicy
	{
		None = 0,
		Retry = 1,
		Backoff = 2,
		Reconnect = 3,
		Practical = 4
	}

	internal readonly struct RegistryRetryOptions
	{
		internal RegistryRetryOptions(
			RegistryRetryPolicy policy,
			int retryCount,
			int delayMs,
			int maxDelayMs,
			int jitterMs)
		{
			this.Policy = policy;
			this.RetryCount = Math.Max(0, retryCount);
			this.DelayMs = Math.Max(0, delayMs);
			this.MaxDelayMs = Math.Max(this.DelayMs, maxDelayMs);
			this.JitterMs = Math.Max(0, jitterMs);
		}

		internal RegistryRetryPolicy Policy { get; }
		internal int RetryCount { get; }
		internal int DelayMs { get; }
		internal int MaxDelayMs { get; }
		internal int JitterMs { get; }

		internal bool RetryEnabled => this.Policy != RegistryRetryPolicy.None && this.RetryCount > 0;
		internal bool UseBackoff => this.Policy is RegistryRetryPolicy.Backoff or RegistryRetryPolicy.Practical;
		internal bool ReconnectOnRetry => this.Policy == RegistryRetryPolicy.Reconnect;
		internal bool ReconnectAfterRetries => this.Policy == RegistryRetryPolicy.Practical;

		internal static RegistryRetryOptions From(SmbConnectionParameters? parms)
		{
			parms ??= SmbConnectionParameters.GetDefault();
			var policy = parms.RegistryRetryPolicy ?? RegistryRetryPolicy.Practical;
			var retryCount = parms.RegistryRetryCount ?? 3;
			var delayMs = parms.RegistryRetryDelayMs ?? 100;
			var maxDelayMs = parms.RegistryRetryMaxDelayMs ?? 1000;
			var jitterMs = parms.RegistryRetryJitterMs ?? 100;
			return new RegistryRetryOptions(policy, retryCount, delayMs, maxDelayMs, jitterMs);
		}
	}

	internal static class RegistryRetryHelper
	{
		private static readonly AsyncLocal<int> s_registryOperationDepth = new();

		internal static void Execute(
			ISmbProviderInfo smb,
			string serverName,
			CancellationToken cancellationToken,
			RegistryRetryOptions options,
			Action<IRegistrySession> action)
		{
			Execute(smb, serverName, cancellationToken, options, session =>
			{
				action(session);
				return true;
			});
		}

		internal static void Execute(
			ISmbProviderInfo smb,
			string serverName,
			CancellationToken cancellationToken,
			Action<IRegistrySession> action)
		{
			Execute(smb, serverName, cancellationToken, session =>
			{
				action(session);
				return true;
			});
		}

		internal static T Execute<T>(
			ISmbProviderInfo smb,
			string serverName,
			CancellationToken cancellationToken,
			RegistryRetryOptions options,
			Func<IRegistrySession, T> operation)
		{
			return ExecuteCore(smb, serverName, cancellationToken, options, operation);
		}

		internal static T Execute<T>(
			ISmbProviderInfo smb,
			string serverName,
			CancellationToken cancellationToken,
			Func<IRegistrySession, T> operation)
		{
			var parms = smb?.GetConnectParametersFor(serverName, true) as SmbConnectionParameters;
			var options = RegistryRetryOptions.From(parms);
			return ExecuteCore(smb, serverName, cancellationToken, options, operation);
		}

		private static T ExecuteCore<T>(
			ISmbProviderInfo smb,
			string serverName,
			CancellationToken cancellationToken,
			RegistryRetryOptions options,
			Func<IRegistrySession, T> operation)
		{
			if (smb == null)
				throw new ArgumentNullException(nameof(smb));
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("Server name must be provided.", nameof(serverName));

			var depth = s_registryOperationDepth.Value;
			bool isNested = depth > 0;
			if (isNested && smb is SmbProviderInfo provider)
			{
				provider.LogDiagnostic(
					$"TBO: Nested registry operation detected for {serverName}. Cached winreg sessions are single-lease; using an uncached session to avoid blocking.");
			}

			s_registryOperationDepth.Value = depth + 1;
			var parms = smb.GetConnectParametersFor(serverName, true) as SmbConnectionParameters;
			var port = parms?.RemotePort;

			int attempt = 0;
			bool reconnectFallbackUsed = false;
			double currentDelayMs = options.DelayMs;
			IRegistrySession? session = null;
			bool sessionIsCached = false;

			try
			{
				while (true)
				{
					cancellationToken.ThrowIfCancellationRequested();

					try
					{
						if (session == null)
						{
							var opened = OpenRegistrySession(smb, serverName, cancellationToken, allowCache: !isNested);
							session = opened.session;
							sessionIsCached = opened.isCached;
						}
						return operation(session);
					}
					catch (Exception ex) when (IsPipeBusy(ex))
					{
						if (!options.RetryEnabled)
							throw;

						attempt++;
						if (attempt > options.RetryCount)
						{
							if (options.ReconnectAfterRetries && !reconnectFallbackUsed)
							{
								reconnectFallbackUsed = true;
								attempt = options.RetryCount;
								currentDelayMs = options.DelayMs;
								if (sessionIsCached)
									TryInvalidateRegistrySession(smb, serverName, RegistrySessionInvalidationReason.PipeBusy);
								DisposeSession(ref session);
								sessionIsCached = false;
								TryForceDisconnect(smb, serverName, port);
								continue;
							}

							throw;
						}

						ApplyDelay(options, ref currentDelayMs, cancellationToken);
					}
					catch (Exception ex) when (IsTransportException(ex))
					{
						if (!options.RetryEnabled)
							throw;

						attempt++;
						if (attempt > options.RetryCount)
						{
							if (options.ReconnectAfterRetries && !reconnectFallbackUsed)
							{
								reconnectFallbackUsed = true;
								attempt = options.RetryCount;
								currentDelayMs = options.DelayMs;
								if (sessionIsCached)
									TryInvalidateRegistrySession(smb, serverName, RegistrySessionInvalidationReason.TransportError);
								DisposeSession(ref session);
								sessionIsCached = false;
								TryForceDisconnect(smb, serverName, port);
								continue;
							}

							throw;
						}

						if (sessionIsCached)
							TryInvalidateRegistrySession(smb, serverName, RegistrySessionInvalidationReason.TransportError);
						DisposeSession(ref session);
						sessionIsCached = false;
						TryForceDisconnect(smb, serverName, port);
						ApplyDelay(options, ref currentDelayMs, cancellationToken);
					}
				}
			}
			finally
			{
				session?.Dispose();
				s_registryOperationDepth.Value = depth;
			}
		}

		private static void TryInvalidateRegistrySession(
			ISmbProviderInfo smb,
			string serverName,
			RegistrySessionInvalidationReason reason)
		{
			if (smb is IRegistrySessionInvalidator invalidator)
				invalidator.InvalidateRegistrySession(serverName, reason);
		}

		private static (IRegistrySession session, bool isCached) OpenRegistrySession(
			ISmbProviderInfo smb,
			string serverName,
			CancellationToken cancellationToken,
			bool allowCache)
		{
			if (allowCache && smb is IRegistrySessionProvider provider)
			{
				var session = provider.OpenRegistrySession(serverName, cancellationToken);
				if (session != null)
					return (session, true);
			}

			var remoteSession = smb.OpenRemoteRegistrySessionAsync(serverName, cancellationToken).GetAwaiter().GetResult();
			return (new RegistrySessionAdapter(remoteSession), false);
		}

		private static void ApplyDelay(RegistryRetryOptions options, ref double currentDelayMs, CancellationToken cancellationToken)
		{
			if (options.DelayMs <= 0)
				return;

			var delayMs = options.UseBackoff ? currentDelayMs : options.DelayMs;
			if (options.UseBackoff)
				currentDelayMs = Math.Min(currentDelayMs * 2, options.MaxDelayMs);

			if (options.JitterMs > 0)
				delayMs += Random.Shared.Next(0, options.JitterMs + 1);

			Task.Delay(TimeSpan.FromMilliseconds(delayMs), cancellationToken).GetAwaiter().GetResult();
		}

		private static bool IsPipeBusy(Exception ex)
		{
			if (ex is NtstatusException nt && nt.StatusCode == Ntstatus.STATUS_PIPE_BUSY)
				return true;

			if (ex is AggregateException agg)
			{
				foreach (var inner in agg.InnerExceptions)
				{
					if (IsPipeBusy(inner))
						return true;
				}
			}

			return ex.InnerException != null && IsPipeBusy(ex.InnerException);
		}

		private static bool IsTransportException(Exception ex)
		{
			if (ex is IOException or SocketException)
				return true;
			return ex.InnerException != null && IsTransportException(ex.InnerException);
		}

		private static void DisposeSession(ref IRegistrySession? session)
		{
			if (session == null)
				return;

			try
			{
				session.Dispose();
			}
			catch
			{
			}
			finally
			{
				session = null;
			}
		}

		private static void TryForceDisconnect(ISmbProviderInfo smb, string serverName, int? port)
		{
			try
			{
				smb.DisconnectServerAsync(serverName, port, true).GetAwaiter().GetResult();
			}
			catch
			{
			}
		}
	}
}
