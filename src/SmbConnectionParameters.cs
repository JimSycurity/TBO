using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Text;
using System.Threading.Tasks;
using Titanis.Net;
using Titanis.Security.Kerberos;
using Titanis.Smb2;
using HexString = Titanis.Cli.HexString;
using RegistryRetryPolicyType = Titanis.Tbo.Smb2.PowerShell.RegistryRetryPolicy;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal class SmbConnectionParameters
	{
		public static SmbConnectionParameters GetDefault()
		{
			return new SmbConnectionParameters
			{
				RemotePort = Smb2Client.TcpPort,
				Dialects = Smb2ConnectionOptions.DefaultSupportedDialects,
				NameResolveOptions = NameResolverOptions.Default,
				Capabilities = Smb2ConnectionOptions.DefaultSmb3Caps,
				EnforceVersionCompliance = false,
				SecurityMode = Smb2SecurityMode.SigningEnabled,
				PreauthSaltLength = Smb2ConnectionOptions.DefaultPreauthSaltLength,
				Ciphers = Smb2ConnectionOptions.DefaultCiphers,
				SigningAlgorithms = Smb2ConnectionOptions.DefaultSigningAlgorithms,
				CompressionCapabilities = CompressionCaps.None,
				CompressionAlgorithms = Smb2ConnectionOptions.DefaultCompressionAlgorithms,
				KdcPort = 88,
				TicketCache = Environment.GetEnvironmentVariable(KerberosClient.Krb5CacheVariableName),
				IncludeRootReparseInfo = false,
				RegistryRetryPolicy = RegistryRetryPolicyType.Practical,
				RegistryRetryCount = 6,
				RegistryRetryDelayMs = 200,
				RegistryRetryMaxDelayMs = 2000,
				RegistryRetryJitterMs = 200
			};
		}

		#region Connection
		[Parameter]
		public string? HostName { get; set; }
		[Parameter]
		public int? RemotePort { get; set; }
		[Parameter]
		public NameResolverOptions? NameResolveOptions { get; set; }

		[Parameter]
		public Smb2Capabilities? Capabilities { get; set; }
		[Parameter]
		public SwitchParameter EnforceVersionCompliance { get; set; }
		[Parameter]
		public Smb2Dialect[]? Dialects { get; set; }
		[Parameter]
		public Smb2SecurityMode? SecurityMode { get; set; }
		[Parameter]
		public SwitchParameter RequireSecureNegotiate { get; set; }
		[Parameter]
		public Guid? ClientGuid { get; set; }
		[Parameter]
		public int? PreauthSaltLength { get; set; }
		[Parameter]
		public Cipher[]? Ciphers { get; set; }
		[Parameter]
		public SigningAlgorithm[]? SigningAlgorithms { get; set; }
		[Parameter]
		public CompressionCaps? CompressionCapabilities { get; set; }
		[Parameter]
		public CompressionAlgorithm[]? CompressionAlgorithms { get; set; }
		[Parameter]
		[Alias("RootReparseInfo")]
		public bool? IncludeRootReparseInfo { get; set; }

		[Parameter]
		[Alias("RetryPolicy", "RegRetryPolicy")]
		public RegistryRetryPolicy? RegistryRetryPolicy { get; set; }
		[Parameter]
		[Alias("RetryCount", "RegRetryCount")]
		public int? RegistryRetryCount { get; set; }
		[Parameter]
		[Alias("RetryDelayMs", "RegRetryDelayMs")]
		public int? RegistryRetryDelayMs { get; set; }
		[Parameter]
		[Alias("RetryMaxDelayMs", "RegRetryMaxDelayMs")]
		public int? RegistryRetryMaxDelayMs { get; set; }
		[Parameter]
		[Alias("RetryJitterMs", "RegRetryJitterMs")]
		public int? RegistryRetryJitterMs { get; set; }

		public SmbConnectionParameters MergeOnto(SmbConnectionParameters baseParams)
		{
			if (baseParams is null) throw new ArgumentNullException(nameof(baseParams));

			static T? PreferRef<T>(T? value, T? fallback) where T : class
				=> value ?? fallback;

			static T? PreferVal<T>(T? value, T? fallback) where T : struct
				=> value ?? fallback;

			static SwitchParameter PreferSwitch(SwitchParameter value, SwitchParameter fallback)
				=> value.IsPresent ? value : fallback;

			SmbConnectionParameters merged = new SmbConnectionParameters
			{
				HostName = PreferRef(this.HostName, baseParams.HostName),
				RemotePort = PreferVal(this.RemotePort, baseParams.RemotePort),
				Capabilities = PreferVal(this.Capabilities, baseParams.Capabilities),
				NameResolveOptions = PreferVal(this.NameResolveOptions, baseParams.NameResolveOptions),
				Dialects = PreferRef(this.Dialects, baseParams.Dialects),
				SecurityMode = PreferVal(this.SecurityMode, baseParams.SecurityMode),
				EnforceVersionCompliance = PreferSwitch(this.EnforceVersionCompliance, baseParams.EnforceVersionCompliance),
				RequireSecureNegotiate = PreferSwitch(this.RequireSecureNegotiate, baseParams.RequireSecureNegotiate),
				ClientGuid = PreferVal(this.ClientGuid, baseParams.ClientGuid),
				PreauthSaltLength = PreferVal(this.PreauthSaltLength, baseParams.PreauthSaltLength),
				Ciphers = PreferRef(this.Ciphers, baseParams.Ciphers),
				SigningAlgorithms = PreferRef(this.SigningAlgorithms, baseParams.SigningAlgorithms),
				CompressionCapabilities = PreferVal(this.CompressionCapabilities, baseParams.CompressionCapabilities),
				CompressionAlgorithms = PreferRef(this.CompressionAlgorithms, baseParams.CompressionAlgorithms),
				IncludeRootReparseInfo = PreferVal(this.IncludeRootReparseInfo, baseParams.IncludeRootReparseInfo),
				RegistryRetryPolicy = PreferVal(this.RegistryRetryPolicy, baseParams.RegistryRetryPolicy),
				RegistryRetryCount = PreferVal(this.RegistryRetryCount, baseParams.RegistryRetryCount),
				RegistryRetryDelayMs = PreferVal(this.RegistryRetryDelayMs, baseParams.RegistryRetryDelayMs),
				RegistryRetryMaxDelayMs = PreferVal(this.RegistryRetryMaxDelayMs, baseParams.RegistryRetryMaxDelayMs),
				RegistryRetryJitterMs = PreferVal(this.RegistryRetryJitterMs, baseParams.RegistryRetryJitterMs),

				UserName = PreferRef(this.UserName, baseParams.UserName),
				UserDomain = PreferRef(this.UserDomain, baseParams.UserDomain),
				Password = PreferRef(this.Password, baseParams.Password),
				Kdc = PreferRef(this.Kdc, baseParams.Kdc),
				KdcPort = PreferVal(this.KdcPort, baseParams.KdcPort),
				NtlmHash = PreferRef(this.NtlmHash, baseParams.NtlmHash),
				AesKey = PreferRef(this.AesKey, baseParams.AesKey),
				DesKey = PreferRef(this.DesKey, baseParams.DesKey),
				Tgt = PreferRef(this.Tgt, baseParams.Tgt),
				Tickets = PreferRef(this.Tickets, baseParams.Tickets),
				TicketCache = PreferRef(this.TicketCache, baseParams.TicketCache),
				Workstation = PreferRef(this.Workstation, baseParams.Workstation)
			};
			return merged;
		}

		internal static SmbConnectionParameters ResolveDefault(object? parameters)
		{
			return parameters as SmbConnectionParameters ?? GetDefault();
		}

		internal static SmbConnectionParameters ResolveOrDefault(ISmbProviderInfo smb, string serverName)
		{
			if (smb is null) throw new ArgumentNullException(nameof(smb));
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("Server name must be provided.", nameof(serverName));

			var parameters = smb.GetConnectParametersFor(serverName, true) as SmbConnectionParameters;
			return parameters ?? ResolveDefault(smb.DefaultConnectParameters);
		}

		internal static SmbConnectionParameters? TryGetServerSpecific(ISmbProviderInfo smb, string serverName)
		{
			if (smb is null) throw new ArgumentNullException(nameof(smb));
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("Server name must be provided.", nameof(serverName));

			return smb.GetConnectParametersFor(serverName, false) as SmbConnectionParameters;
		}

		internal static SmbConnectionParameters MergeForServer(
			ISmbProviderInfo smb,
			string serverName,
			SmbConnectionParameters overrides)
		{
			if (overrides is null) throw new ArgumentNullException(nameof(overrides));
			var baseParams = ResolveOrDefault(smb, serverName);
			return overrides.MergeOnto(baseParams);
		}

		internal static SmbConnectionParameters MergeDefaults(
			ISmbProviderInfo smb,
			SmbConnectionParameters overrides)
		{
			if (overrides is null) throw new ArgumentNullException(nameof(overrides));
			var baseParams = ResolveDefault(smb.DefaultConnectParameters);
			return overrides.MergeOnto(baseParams);
		}

		public Smb2ConnectionOptions ToConnectionOptions()
		{
			// TODO: Ensure the parameter block is complete

			SmbConnectionParameters parms = this;
			Smb2ConnectionOptions connOptions = new Smb2ConnectionOptions()
			{
				Capabilities = parms.Capabilities.Value,
				EnforcesVersionCompliance = parms.EnforceVersionCompliance,
				SupportedDialects = parms.Dialects,
				SecurityMode = parms.SecurityMode.Value,
				RequiresSecureNegotiate = parms.RequireSecureNegotiate,
				ClientGuid = parms.ClientGuid ?? Guid.NewGuid(),
				PreauthSaltLength = parms.PreauthSaltLength.Value,
				SupportedCiphers = parms.Ciphers,
				SupportedSigningAlgorithms = parms.SigningAlgorithms,
				CompressionCaps = parms.CompressionCapabilities.Value,
				SupportedCompressionAlgorithms = parms.CompressionAlgorithms,
			};
			return connOptions;
		}
		#endregion

		[Parameter]
		public string? UserName { get; set; }
		[Parameter]
		public string? UserDomain { get; set; }
		[Parameter]
		public string? Password { get; set; }
		[Parameter]
		public NtlmHashInput? NtlmHash { get; set; }
		[Parameter]
		public HexString? AesKey { get; set; }
		[Parameter]
		public HexString? DesKey { get; set; }
		[Parameter]
		public string? Tgt { get; set; }
		[Parameter]
		public string[]? Tickets { get; set; }
		[Parameter]
		public string? TicketCache { get; set; }
		[Parameter]
		public string? Kdc { get; set; }
		[Parameter]
		public int? KdcPort { get; set; }
		[Parameter]
		public string? Workstation { get; set; }
	}
}
