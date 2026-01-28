using System;
using System.Threading;
using System.Threading.Tasks;
using Titanis.Smb2;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class MockSmbProviderInfo : ISmbProviderInfo
	{
		public Smb2Client? SmbClient { get; set; }
		private SmbConnectionParameters? _defaultConnectParameters = SmbConnectionParameters.GetDefault();
		public object? DefaultConnectParameters
		{
			get => this._defaultConnectParameters;
			set
			{
				if (value is null)
					throw new ArgumentNullException(nameof(value));
				if (value is not SmbConnectionParameters parameters)
					throw new ArgumentException("DefaultConnectParameters must be a SmbConnectionParameters instance.", nameof(value));
				this._defaultConnectParameters = parameters;
			}
		}

		public Func<string, bool, object?>? GetConnectParametersForFunc { get; set; }
		public Action<string, object>? SetConnectParametersAction { get; set; }
		public Func<string, CancellationToken, Task<ServerServiceSession>>? OpenServerServiceSessionAsyncFunc { get; set; }
		public Func<string, CancellationToken, Task<RemoteRegistrySession>>? OpenRemoteRegistrySessionAsyncFunc { get; set; }
		public Func<string, int?, Task>? DisconnectServerAsyncFunc { get; set; }
		public Func<Task>? DisconnectAllAsyncFunc { get; set; }
		public Action<string, Exception>? LogExceptionAction { get; set; }

		Smb2Client ISmbProviderInfo.SmbClient
			=> this.SmbClient ?? throw new InvalidOperationException("SmbClient was not configured on MockSmbProviderInfo.");

		object? ISmbProviderInfo.DefaultConnectParameters
		{
			get => this._defaultConnectParameters;
			set
			{
				if (value is null)
					throw new ArgumentNullException(nameof(value));
				if (value is not SmbConnectionParameters parameters)
					throw new ArgumentException("DefaultConnectParameters must be a SmbConnectionParameters instance.", nameof(value));
				this._defaultConnectParameters = parameters;
			}
		}

		object? ISmbProviderInfo.GetConnectParametersFor(string serverName, bool defaultIfNone)
		{
			if (this.GetConnectParametersForFunc != null)
				return this.GetConnectParametersForFunc(serverName, defaultIfNone);
			return defaultIfNone ? this._defaultConnectParameters : null;
		}

		void ISmbProviderInfo.SetConnectParameters(string serverName, object parameters)
		{
			if (this.SetConnectParametersAction == null)
				throw new InvalidOperationException("SetConnectParametersAction is not configured.");
			this.SetConnectParametersAction(serverName, parameters);
		}

		Task<ServerServiceSession> ISmbProviderInfo.OpenServerServiceSessionAsync(string serverName, CancellationToken cancellationToken)
		{
			if (this.OpenServerServiceSessionAsyncFunc == null)
				throw new InvalidOperationException("OpenServerServiceSessionAsyncFunc is not configured.");
			return this.OpenServerServiceSessionAsyncFunc(serverName, cancellationToken);
		}

		Task<RemoteRegistrySession> ISmbProviderInfo.OpenRemoteRegistrySessionAsync(string serverName, CancellationToken cancellationToken)
		{
			if (this.OpenRemoteRegistrySessionAsyncFunc == null)
				throw new InvalidOperationException("OpenRemoteRegistrySessionAsyncFunc is not configured.");
			return this.OpenRemoteRegistrySessionAsyncFunc(serverName, cancellationToken);
		}

		Task ISmbProviderInfo.DisconnectServerAsync(string serverName, int? port)
			=> this.DisconnectServerAsyncFunc?.Invoke(serverName, port) ?? Task.CompletedTask;

		Task ISmbProviderInfo.DisconnectAllAsync()
			=> this.DisconnectAllAsyncFunc?.Invoke() ?? Task.CompletedTask;

		void ISmbProviderInfo.LogException(string context, Exception ex)
			=> this.LogExceptionAction?.Invoke(context, ex);
	}
}
