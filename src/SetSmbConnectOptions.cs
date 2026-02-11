using System;
using System.Management.Automation;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public abstract class SmbCmdlet : PSCmdlet
	{
		internal static ISmbProviderInfo? ProviderInfoOverride { get; set; }
		internal const string CacheIngestEnvVar = "TITANIS_TBO_CACHE_INGEST";

		protected override void ProcessRecord()
		{
			var smb = ProviderInfoOverride ?? (ISmbProviderInfo)this.SessionState.Provider.GetOne(SmbProvider.ProviderName);
			this.ProcessRecord(smb);
		}

		protected abstract void ProcessRecord(ISmbProviderInfo smb);

		protected bool ResolveCacheIngestionEnabled(SwitchParameter cache, string cacheParamName = "Cache")
		{
			// Allow explicit -Cache:$false overrides by checking whether the parameter was bound.
			// SwitchParameter.IsPresent alone cannot distinguish "not specified" from "-Cache:$false".
			if (!string.IsNullOrWhiteSpace(cacheParamName)
				&& this.MyInvocation.BoundParameters.ContainsKey(cacheParamName))
			{
				return cache.IsPresent;
			}

			var env = Environment.GetEnvironmentVariable(CacheIngestEnvVar);
			if (string.IsNullOrWhiteSpace(env))
				return false;

			return TboCacheDatabase.IsTruthy(env);
		}

		protected void LogVerbose(ISmbProviderInfo smb, string message)
		{
			if (string.IsNullOrWhiteSpace(message))
				return;

			this.WriteVerbose(message);
			if (smb is SmbProviderInfo provider)
				provider.LogVerbose(message);
		}

		protected void LogWarning(ISmbProviderInfo smb, string message)
		{
			if (string.IsNullOrWhiteSpace(message))
				return;

			this.WriteWarning(message);
			if (smb is SmbProviderInfo provider)
				provider.LogWarning(message, emitToConsole: false);
		}

		protected void LogException(ISmbProviderInfo smb, string context, Exception ex, bool emitWarning = true)
		{
			if (string.IsNullOrWhiteSpace(context) || ex == null)
				return;

			smb.LogException(context, ex);
			if (!emitWarning)
				return;

			var message = $"{context}: {ex.Message}";
			this.WriteWarning(message);
			if (smb is SmbProviderInfo provider)
				provider.LogWarning(message, emitToConsole: false);
		}
	}

	public abstract class SetTBOConnectOptionsBase : SmbCmdlet, IDynamicParameters
	{
		[Parameter(Position = 0)]
		public string? ServerName { get; set; }

		private readonly SmbConnectionParameters _parms = new SmbConnectionParameters();
		public object GetDynamicParameters()
			=> this._parms;

		protected override void ProcessRecord(ISmbProviderInfo smb)
		{
			if (string.IsNullOrEmpty(this.ServerName))
			{
				this.LogVerbose(smb, this.DefaultScopeMessage);
				smb.DefaultConnectParameters = SmbConnectionParameters.MergeDefaults(smb, this._parms);
				return;
			}

			var parms = SmbConnectionParameters.MergeForServer(smb, this.ServerName, this._parms);
			smb.SetConnectParameters(this.ServerName, parms);
		}

		protected virtual string DefaultScopeMessage
			=> "Setting default connection parameters (no server specified)";
	}

	[Cmdlet(VerbsCommon.Set, "TBOConnectOptions")]
	public sealed class SetTBOConnectOptions : SetTBOConnectOptionsBase
	{
	}

	[Cmdlet(VerbsCommon.Set, "TBOSmbConnectOptions")]
	[Obsolete("Use Set-TBOConnectOptions.")]
	public sealed class SetTBOSmbConnectOptions : SetTBOConnectOptionsBase
	{
		protected override string DefaultScopeMessage
			=> "Setting default SMB connection parameters (no server specified)";
	}
}
