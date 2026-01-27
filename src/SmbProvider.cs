using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Provider;
using System.Management.Automation.Remoting;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Titanis;
using Titanis.Cli;
using Titanis.DceRpc.Client;
using Titanis.Net;
using Titanis.Security;
using Titanis.Security.Kerberos;
using Titanis.Security.Ntlm;
using Titanis.Security.Spnego;
using Titanis.Winterop.Security;
using Smb2AccessRights = Titanis.Smb2.Smb2FileAccessRights;
using Winterop = Titanis.Winterop;
using Titanis.Smb2;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public static class SmbItemClasses
	{
		public const string File = "File";
		public const string Directory = "Directory";
		public const string Symlink = "Symlink";
		public const string SymlinkDir = "SymlinkDir";
		public const string MountPoint = "MountPoint";
		public const string Junction = "Junction";
	}

	/// <summary>
	/// Implements a <see cref="NavigationCmdletProvider"/> for the SMB namespace.
	/// </summary>
	[CmdletProvider(ProviderName, ProviderCapabilities.None)]
	public partial class SmbProvider : NavigationCmdletProvider, ISecurityDescriptorCmdletProvider
	{
		public const string ProviderName = "TBO.Smb2";

		public SmbProvider()
		{
		}

		protected override ProviderInfo Start(ProviderInfo providerInfo)
		{
			return new SmbProviderInfo(base.Start(providerInfo), this);
		}

		internal SmbProviderInfo smb => ((SmbProviderInfo)this.ProviderInfo);
		public Smb2Client SmbClient => this.smb.SmbClient;

		private void BeginOperation(Action<CancellationToken> func)
		{
			var prevSource = this._cancelSource;
			var cancelSource = prevSource ??= (this._cancelSource = new CancellationTokenSource());

			try
			{
				func(cancelSource.Token);
			}
			finally
			{
				this._cancelSource = prevSource;
			}
		}
		private TResult BeginOperation<TResult>(Func<CancellationToken, TResult> func)
		{
			var prevSource = this._cancelSource;
			var cancelSource = prevSource ??= (this._cancelSource = new CancellationTokenSource());

			try
			{
				return func(cancelSource.Token);
			}
			finally
			{
				this._cancelSource = prevSource;
			}
		}

		private CancellationTokenSource? _cancelSource;
		protected override void StopProcessing()
		{
			this._cancelSource?.Cancel();
		}
		protected override void Stop()
		{
			base.Stop();
		}

		protected override Collection<PSDriveInfo> InitializeDefaultDrives()
		{
			return new Collection<PSDriveInfo>() { new PSDriveInfo("tbo-smb", this.ProviderInfo, "smb://", "Titanis TBO SMB drive", null) };
		}

		protected override bool IsValidPath(string path)
		{
			return UncPath.TryParse(path, out _);
		}

		#region Drives
		protected override object NewDriveDynamicParameters()
		{
			return new SmbConnectionParameters();
		}
		protected override PSDriveInfo NewDrive(PSDriveInfo drive)
		{
			if (drive.Root == "smb://")
				return new SmbRootDriveInfo(drive);

			return this.BeginOperation(cancellationToken =>
			{
				var uncPath = UncPath.Parse(drive.Root);

				var baseParms = this.smb.GetConnectParametersFor(uncPath.ServerName, true);
				var parms = (SmbConnectionParameters)this.DynamicParameters;
				parms = parms.MergeOnto(baseParms);
				this.smb.SetConnectParameters(uncPath.ServerName, parms);

				if (string.IsNullOrEmpty(uncPath.ShareName))
					throw new ArgumentException("The UNC path must include a share name");

				var client = this.SmbClient;
				var share = client.GetShare(uncPath, cancellationToken).Result;
				try
				{
					var conn_ = share;
					share = null;

					return new SmbShareDriveInfo(drive, this, uncPath, share);
				}
				finally
				{
					share?.Dispose();
				}
			});
		}
		#endregion

		protected override object NewItemDynamicParameters(string path, string itemTypeName, object newItemValue)
		{
			return GetNewItemParamsCore(itemTypeName);
		}

		private static SmbNewItemParams? GetNewItemParamsCore(string itemTypeName)
		{
			if (itemTypeName != null)
			{
				if (itemTypeName.Equals(SmbItemClasses.File, StringComparison.OrdinalIgnoreCase))
					return new SmbNewFileItemParams();
				else if (itemTypeName.Equals(SmbItemClasses.Directory, StringComparison.OrdinalIgnoreCase))
					return new SmbNewDirectoryItemParams();
				else if (itemTypeName.Equals(SmbItemClasses.MountPoint, StringComparison.OrdinalIgnoreCase))
					return new SmbMountPointItemParams();
				else if (itemTypeName.Equals(SmbItemClasses.Junction, StringComparison.OrdinalIgnoreCase))
					return new SmbMountPointItemParams();
				else if (itemTypeName.Equals(SmbItemClasses.SymlinkDir, StringComparison.OrdinalIgnoreCase))
					return new SmbSymlinkDirItemParams();
				else if (itemTypeName.Equals(SmbItemClasses.Symlink, StringComparison.OrdinalIgnoreCase))
					return new SmbSymlinkItemParams();
			}
			return new SmbNewFileItemParams();
		}

		protected override void NewItem(string path, string itemTypeName, object newItemValue)
		{
			var snapshotPath = ResolveSnapshotPath(path);
			if (snapshotPath.HasTimeWarpToken)
				throw new NotSupportedException("Snapshot paths are read-only.");

			this.BeginOperation(cancellationToken =>
			{
				var newItemParams = this.DynamicParameters as SmbNewItemParams ?? new SmbNewFileItemParams();
				return newItemParams.Create(this.SmbClient, snapshotPath.ResolvedPath, cancellationToken);
			});
		}

		protected override bool IsItemContainer(string path)
		{
			if (!UncPath.TryParse(path, out var parsedPath))
				return false;

			var snapshotPath = ResolveSnapshotPath(parsedPath!);
			UncPath uncPath = snapshotPath.ResolvedPath;

			if (string.IsNullOrEmpty(uncPath.ShareRelativePath))
				return true;

			return this.BeginOperation(cancellationToken =>
			{
				using (var file = this.smb.SmbClient.CreateFileAsync(uncPath, new Smb2CreateInfo
				{
					CreateDisposition = Smb2CreateDisposition.Open,
					DesiredAccess = (uint)Smb2AccessRights.DefaultOpenReadAccess,
					ShareAccess = Smb2ShareAccess.Read,
					ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
					CreateOptions = Smb2FileCreateOptions.SynchronousIoNonalert | Smb2FileCreateOptions.OpenForBackupIntent,
					FileAttributes = Winterop.FileAttributes.Normal,
					TimeWarpToken = snapshotPath.TimeWarpToken
				}, FileAccess.Read, cancellationToken).Result)
				{
					return file.IsDirectory;
				}
			});
		}

		protected override void GetItem(string path)
		{
			base.GetItem(path);
		}

		protected override void GetChildItems(string path, bool recurse)
		{
			base.GetChildItems(path, recurse);
		}

		protected override bool ConvertPath(string path, string filter, ref string updatedPath, ref string updatedFilter)
		{
			return base.ConvertPath(path, filter, ref updatedPath, ref updatedFilter);
		}

		protected override void GetChildItems(string path, bool recurse, uint depth)
		{
			var snapshotPath = ResolveSnapshotPath(path);
			UncPath uncPath = snapshotPath.ResolvedPath;

			this.BeginOperation(cancellationToken =>
			{
				using (var dir = (Smb2Directory)this.smb.SmbClient.CreateFileAsync(uncPath, new Smb2CreateInfo
				{
					CreateDisposition = Smb2CreateDisposition.Open,
					Priority = Smb2Priority.OpenDir,
					DesiredAccess = (uint)Smb2AccessRights.DefaultOpenDirAccess,
					ShareAccess = Smb2ShareAccess.DefaultDirShare,
					FileAttributes = Winterop.FileAttributes.None,
					CreateOptions = Smb2FileCreateOptions.Directory
						| Smb2FileCreateOptions.SynchronousIoNonalert
						| Smb2FileCreateOptions.OpenForBackupIntent,
					ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
					RequestMaximalAccess = true,
					QueryOnDiskId = true,
					TimeWarpToken = snapshotPath.TimeWarpToken,
					OplockLevel = Smb2OplockLevel.None
				}, FileAccess.Read, cancellationToken).Result)
				{
					foreach (var entry in dir.QueryDirAsync("*", Smb2Directory.Smb2DirQueryOptions.QueryReparseInfo, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken).Result)
					{
						if (string.IsNullOrEmpty(entry.FileName))
							continue;
						if (entry.FileName is "." or "..")
							continue;
						UncPath itemPath = snapshotPath.OriginalPath.Append(entry.FileName);
						var smbItem = new SmbItem(itemPath, entry);
						this.WriteItemObject(smbItem, itemPath.ToString(), 0 != (entry.FileAttributes & Winterop.FileAttributes.Directory));
					}
				}
			});
		}

		protected override string GetChildName(string path)
		{
			return base.GetChildName(path);
		}

		protected override void GetChildNames(string path, ReturnContainers returnContainers)
		{
			base.GetChildNames(path, returnContainers);
		}

		protected override bool ItemExists(string path)
		{
			CancellationToken token = CancellationToken.None;

			if (!UncPath.TryParse(path, out UncPath uncPath))
				return false;

			var snapshotPath = ResolveSnapshotPath(uncPath);
			uncPath = snapshotPath.ResolvedPath;

			if (string.IsNullOrEmpty(uncPath.ShareRelativePath))
				return true;

			return this.BeginOperation(cancellationToken =>
			{
				try
				{
					using (this.SmbClient.CreateFileAsync(uncPath, new Smb2CreateInfo
					{
						CreateDisposition = Smb2CreateDisposition.Open,
						DesiredAccess = (uint)Smb2AccessRights.DefaultOpenReadAccess,
						ShareAccess = Smb2ShareAccess.Read,
						ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
						CreateOptions = Smb2FileCreateOptions.SynchronousIoNonalert
							| Smb2FileCreateOptions.OpenReparsePoint
							| Smb2FileCreateOptions.OpenForBackupIntent,
						FileAttributes = Winterop.FileAttributes.Normal,
						TimeWarpToken = snapshotPath.TimeWarpToken
					}, FileAccess.Read, token).Result)
					{
						return true;
					}
				}
				catch
				{
					return false;
				}
			});
		}
	}

	partial class SmbProvider : IContentCmdletProvider
	{
		public void ClearContent(string path)
		{
			throw new NotImplementedException();
		}

		public object ClearContentDynamicParameters(string path)
		{
			throw new NotImplementedException();
		}

		public IContentReader GetContentReader(string path)
		{
			var snapshotPath = ResolveSnapshotPath(path);
			UncPath uncPath = snapshotPath.ResolvedPath;

			return this.BeginOperation(cancellationToken =>
			{
				var parms = this.DynamicParameters as SmbGetContentParams;
				var encoding = parms?.Encoding ?? Encoding.UTF8;
				var raw = parms?.Raw.IsPresent ?? false;

				var file = (Smb2OpenFile)this.smb.SmbClient.CreateFileAsync(uncPath, new Smb2CreateInfo
				{
					CreateDisposition = Smb2CreateDisposition.Open,
					DesiredAccess = (uint)Smb2AccessRights.DefaultOpenReadAccess,
					ShareAccess = Smb2ShareAccess.Read,
					ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
					CreateOptions = Smb2FileCreateOptions.NonDirectory | Smb2FileCreateOptions.SynchronousIoNonalert,
					FileAttributes = Winterop.FileAttributes.Normal,
					TimeWarpToken = snapshotPath.TimeWarpToken
				}, FileAccess.Read, cancellationToken).Result;
				var stream = file.GetStream(true);
				return (IContentReader)new SmbContentReader(stream, encoding, raw);
			});
		}

		public object GetContentReaderDynamicParameters(string path)
		{
			return new SmbGetContentParams();
		}

		public IContentWriter GetContentWriter(string path)
		{
			throw new NotImplementedException();
		}

		public object GetContentWriterDynamicParameters(string path)
		{
			return null;
		}
	}

	public partial class SmbProviderInfo : ProviderInfo, ISmb2TraceCallback
	{
		private static readonly AsyncLocal<bool> s_forceZeroCreditFallback = new AsyncLocal<bool>();

		private sealed class ConnectionOptionsScope : IDisposable
		{
			private readonly bool _previous;

			public ConnectionOptionsScope(bool enabled)
			{
				_previous = s_forceZeroCreditFallback.Value;
				s_forceZeroCreditFallback.Value = enabled;
			}

			public void Dispose()
			{
				s_forceZeroCreditFallback.Value = _previous;
			}
		}

		internal static IDisposable EnableZeroCreditFallbackScope()
			=> new ConnectionOptionsScope(true);
		internal SmbProviderInfo(ProviderInfo providerInfo, SmbProvider provider) : base(providerInfo)
		{
			this.Provider = provider;

			var socketService = new PlatformSocketService(this, null);
			this._rpcClient = new RpcClient(socketService, this, this, null, null);

			this._log = CreateLocalLog(out this._logWriter);
			ISmb2TraceCallback traceCallback = this._log != null
				? new Smb2Logger(this._log, this)
				: this;

			this.SmbClient = CreateSmbClient(socketService, traceCallback, this._log, Smb2FileCreateOptions.OpenForBackupIntent);
			this.RpcSmbClient = CreateSmbClient(socketService, traceCallback, this._log, Smb2FileCreateOptions.None);
		}

		public SmbProvider Provider { get; }
		public Smb2Client SmbClient { get; private set; }
		public Smb2Client RpcSmbClient { get; private set; }
		private readonly ILog? _log;
		private readonly TextWriter? _logWriter;

		private Smb2Client CreateSmbClient(
			ISocketService socketService,
			ISmb2TraceCallback traceCallback,
			ILog? log,
			Smb2FileCreateOptions requiredCreateOptions)
		{
			var client = new Smb2Client(
				this,
				socketService,
				this,
				traceCallback,
				log
				);
			client.RequiredCreateOptions = requiredCreateOptions;
			return client;
		}

		#region Connection parameters
		private SmbConnectionParameters _defaultConnectParameters = SmbConnectionParameters.GetDefault();
		internal SmbConnectionParameters? DefaultConnectParameters
		{
			get => _defaultConnectParameters;
			set
			{
				if (value is null) throw new ArgumentNullException(nameof(value));
				_defaultConnectParameters = value;
			}
		}

		private Dictionary<string, SmbConnectionParameters> _connectParams = new Dictionary<string, SmbConnectionParameters>(StringComparer.OrdinalIgnoreCase);

		internal SmbConnectionParameters? GetConnectParametersFor(
			string serverName,
			bool defaultIfNone
			)
		{
			this._connectParams.TryGetValue(serverName, out var parms);
			if (defaultIfNone && parms == null)
				return DefaultConnectParameters;

			return parms;
		}
		internal void SetConnectParameters(
			string serverName,
			SmbConnectionParameters parameters
			)
		{
			if (string.IsNullOrEmpty(serverName)) throw new ArgumentException($"'{nameof(serverName)}' cannot be null or empty.", nameof(serverName));
			if (parameters is null) throw new ArgumentNullException(nameof(parameters));

			lock (this._connectParams)
			{
				this._connectParams[serverName] = parameters;
			}
		}
		#endregion

		private static ILog? CreateLocalLog(out TextWriter? writer)
		{
			writer = null;

			var setting = Environment.GetEnvironmentVariable("TITANIS_TBO_LOG");
			if (string.IsNullOrWhiteSpace(setting))
				return null;

			string path = setting;
			if (setting.Equals("1", StringComparison.OrdinalIgnoreCase)
				|| setting.Equals("true", StringComparison.OrdinalIgnoreCase)
				|| setting.Equals("yes", StringComparison.OrdinalIgnoreCase))
			{
				path = Path.Combine(Path.GetTempPath(), "Titanis.TBO.Smb2.log");
			}

			var dir = Path.GetDirectoryName(path);
			if (!string.IsNullOrWhiteSpace(dir))
				Directory.CreateDirectory(dir);

			writer = new StreamWriter(new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
			{
				AutoFlush = true
			};

			var log = new TextWriterLog(writer)
			{
				LogLevel = LogMessageSeverity.Diagnostic,
				Format = LogFormat.TextWithTimestamp
			};
			log.WriteInfo($"TBO logging enabled: {path}");
			return log;
		}
	}

	partial class SmbProviderInfo : IClientCredentialService
	{

		class KdcLocator : IKdcLocator
		{
			private readonly EndPoint _kdcEP;

			public KdcLocator(EndPoint kdcEP)
			{
				this._kdcEP = kdcEP;
			}
			public EndPoint LocateKdc(string realm, LocateKdcOptions options)
			{
				return this._kdcEP;
			}
		}

		AuthClientContext? IClientCredentialService.GetAuthContextForResource(
			string resourceType,
			object resourceKey,
			SecurityCapabilities requiredCaps,
			AuthOptions options)
		{
			ServicePrincipalName? serviceSpn = resourceKey as ServicePrincipalName;

			string? serverName = resourceType switch
			{
				ResourceTypes.Server when resourceKey is string server => server,
				ResourceTypes.Service when serviceSpn != null => serviceSpn.ServiceInstance,
				ResourceTypes.SmbShare when resourceKey is UncPath sharePath => sharePath.ServerName,
				_ => null
			};

			if (string.IsNullOrEmpty(serverName))
				return null;

			var parms = this.GetConnectParametersFor(serverName, true) ?? SmbConnectionParameters.GetDefault();

			// Create SPNEGO context required by SMB2
			var authContext = new SpnegoClientContext();

			ServicePrincipalName targetSpn;
			if (resourceType == ResourceTypes.Service && serviceSpn != null)
			{
				var targetHost = string.IsNullOrEmpty(parms.HostName) ? serviceSpn.ServiceInstance : parms.HostName;
				targetSpn = new ServicePrincipalName(serviceSpn.ServiceClass, targetHost);
			}
			else
			{
				var targetHost = string.IsNullOrEmpty(parms.HostName) ? serverName : parms.HostName;
				targetSpn = new ServicePrincipalName(ServiceClassNames.Cifs, targetHost);
			}

			bool hasKerberosParams =
				!string.IsNullOrEmpty(parms.Kdc)
				|| !string.IsNullOrEmpty(parms.Tgt)
				|| (parms.Tickets?.Length > 0)
				|| !string.IsNullOrEmpty(parms.TicketCache)
				|| parms.Password != null
				|| parms.NtlmHash != null
				|| parms.AesKey != null
				|| parms.DesKey != null;

			if (hasKerberosParams)
			{
				IKdcLocator? locator = null;
				if (!string.IsNullOrEmpty(parms.Kdc))
				{
					var port = parms.KdcPort.Value;
					if (IPAddress.TryParse(serverName, out var _))
						this.WriteWarning("The server name within the UNC path is an IP address.  This will probably result in Kerberos authentication failing.");

					EndPoint kdcEP;
					if (IPAddress.TryParse(parms.Kdc, out var kdcAddr))
						kdcEP = new IPEndPoint(kdcAddr, port);
					else
						kdcEP = new DnsEndPoint(parms.Kdc, port);

					locator = new KdcLocator(kdcEP);
				}

				var krb = new KerberosClient(locator);
				if (!string.IsNullOrEmpty(parms.Workstation))
				{
					if (IPAddress.TryParse(parms.Workstation, out var workstationIp))
						krb.Workstation = HostAddress.FromIPAddress(workstationIp);
					else
						krb.Workstation = HostAddress.FromNetbiosName(parms.Workstation);
				}

				if (!string.IsNullOrEmpty(parms.TicketCache))
				{
					krb.TicketCache = new TicketCacheFile(parms.TicketCache, krb);
				}

				var authUser = parms.UserName;
				var authRealm = parms.UserDomain;
				var effectiveUser = authUser;

				TicketInfo? ticket = krb.TicketCache.GetTicketFromCache(targetSpn, effectiveUser);
				if (ticket != null)
				{
					effectiveUser ??= ticket.UserName;
					authRealm ??= ticket.UserRealm;
				}

				if (ticket is null && parms.Tickets != null)
				{
					foreach (var ticketFile in parms.Tickets)
					{
						if (string.IsNullOrWhiteSpace(ticketFile))
							continue;

						var fileCache = new TicketCacheFile(ticketFile, krb);
						foreach (var fileTicket in fileCache.GetAllTickets())
						{
							if (ticket is null && CheckMatchingTicket(targetSpn, fileTicket, ref effectiveUser, ref authRealm))
								ticket = fileTicket;

							krb.ImportTicket(fileTicket);
						}
					}
				}

				if (!string.IsNullOrEmpty(parms.Tgt))
				{
					var tgtCache = new TicketCacheFile(parms.Tgt, krb);
					foreach (var tgtTicket in tgtCache.GetAllTickets())
					{
						if (tgtTicket.IsTgt && tgtTicket.IsCurrent)
						{
							if ((authUser == null || string.Equals(authUser, tgtTicket.UserName, StringComparison.OrdinalIgnoreCase))
								&& (authRealm == null || string.Equals(authRealm, tgtTicket.UserRealm, StringComparison.OrdinalIgnoreCase)))
							{
								authUser ??= tgtTicket.UserName;
								authRealm ??= tgtTicket.UserRealm;
								krb.ImportTicket(tgtTicket);
							}
						}
					}
				}

				KerberosCredential? cred = null;
				if (!string.IsNullOrEmpty(authUser) && !string.IsNullOrEmpty(authRealm))
				{
					if (parms.Password != null)
						cred = new KerberosPasswordCredential(authUser, authRealm, parms.Password);
					else if (parms.NtlmHash != null)
						cred = new KerberosKeyCredential(authUser, authRealm, EType.Rc4Hmac, parms.NtlmHash.NtHash);
					else if (parms.AesKey != null)
						cred = new KerberosKeyCredential(authUser, authRealm, parms.AesKey.Bytes.Length switch
						{
							(128 / 8) => EType.Aes128CtsHmacSha1_96,
							(256 / 8) => EType.Aes256CtsHmacSha1_96,
							_ => throw new ArgumentException("The AES key is not the correct size for AES 128 or AES 256.")
						}, parms.AesKey.Bytes);
					else if (parms.DesKey != null)
						cred = new KerberosKeyCredential(authUser, authRealm, EType.DesCbcMd5, parms.DesKey.Bytes);
				}

				if (ticket is null && cred != null && locator != null)
				{
					try
					{
						var ticketParams = krb.GetDefaultTicketOptions(null);
						ticket = krb.GetTicketAsync(
							targetSpn,
							cred.Realm,
							cred,
							ticketParams,
							CancellationToken.None).GetAwaiter().GetResult();
					}
					catch (Exception ex)
					{
						this.WriteWarning($"Failed to acquire Kerberos ticket for {targetSpn}: {ex.Message}");
					}
				}

				if (ticket != null)
				{
					cred ??= new KerberosNullCredential(authUser ?? ticket.UserName, authRealm ?? ticket.ServiceRealm ?? ticket.UserRealm);
					var krbContext = new KerberosClientContext(cred, krb, targetSpn, ticket);
					krbContext.RequiredCapabilities = requiredCaps;
					authContext.Contexts.Add(krbContext);
				}
			}

			// Create NTLM context based on parameters
			NtlmCredential? ntlmCred;
			if (parms.Password != null)
			{
				ntlmCred = new NtlmPasswordCredential(parms.UserName, parms.UserDomain, parms.Password);
			}
			else if (parms.NtlmHash != null)
			{
				var lmHash = parms.NtlmHash.LmHash ?? new byte[16];
				ntlmCred = new NtlmHashCredential(
					parms.UserName,
					parms.UserDomain,
					new Buffer128(lmHash),
					new Buffer128(parms.NtlmHash.NtHash));
			}
			else
				ntlmCred = null;

			if (ntlmCred != null)
			{
				var ntlmContext = new NtlmClientContext(ntlmCred, useNtlmV2: true)
				{
					Workstation = parms.Workstation,
					WorkstationDomain = parms.UserDomain,
					TargetSpn = targetSpn,
					ClientChannelBindingsUnhashed = new byte[16]
				};
				ntlmContext.RequiredCapabilities = requiredCaps;
				ntlmContext.ClientConfigFlags |= NegotiateFlags.D_NegotiateSign;
				// UNDONE: SMB doesn't use the provider's sealing capability
				//if (this.Encrypt.IsSet)
				//	ntlmContext.ClientConfigFlags |= NegotiateFlags.E_NegotiateSeal;

				authContext.Contexts.Add(ntlmContext);
			}

			return authContext;
		}

		private void WriteWarning(string v)
		{
			if (string.IsNullOrWhiteSpace(v))
				return;

			try
			{
				System.Diagnostics.Trace.TraceWarning(v);
			}
			catch
			{
			}

			try
			{
				Console.Error.WriteLine($"WARNING: {v}");
			}
			catch
			{
			}
		}

		private static bool CheckMatchingTicket(ServicePrincipalName targetSpn, TicketInfo ticket, ref string? userName, ref string? userRealm)
		{
			if (!ticket.TargetSpn.Equals(targetSpn))
				return false;

			if (
				(userName == null || string.Equals(userName, ticket.UserName, StringComparison.OrdinalIgnoreCase))
				&& (userRealm == null || string.Equals(userRealm, ticket.UserRealm, StringComparison.OrdinalIgnoreCase))
				)
			{
				userName ??= ticket.UserName;
				userRealm ??= ticket.UserRealm;
				return true;
			}

			return false;
		}
	}

	partial class SmbProviderInfo : INameResolverService
	{
		public Task<IPAddress[]> ResolveAsync(string hostName, CancellationToken cancellationToken)
		{
			var parms = this.GetConnectParametersFor(hostName, false);

			if (parms != null)
				hostName = parms.HostName;

			return PlatformNameResolverService.ResolveAsync(hostName, this.DefaultConnectParameters.NameResolveOptions.Value, null, cancellationToken);
		}
	}
	partial class SmbProviderInfo : ISmbOptionsService
	{
		public Smb2ConnectionOptions? GetConnectionOptionsFor(string serverName)
		{
			var parms = this.GetConnectParametersFor(serverName, true);
			var options = parms.ToConnectionOptions();
			if (s_forceZeroCreditFallback.Value)
				options.AllowZeroCreditFallback = true;
			return options;
		}
	}
}
