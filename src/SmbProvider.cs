using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Provider;
using System.Management.Automation.Remoting;
using System.Net;
using System.Reflection;
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

		#region Logging helpers
		private void LogDiagnostic(string message)
			=> this.smb.LogDiagnostic(message);

		private void LogWarning(string message)
			=> this.smb.LogWarning(message);

		private void LogException(string context, Exception ex)
			=> this.smb.LogException(context, ex);
		#endregion

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

				var overrides = this.DynamicParameters as SmbConnectionParameters ?? new SmbConnectionParameters();
				var parms = SmbConnectionParameters.MergeForServer(this.smb, uncPath.ServerName, overrides);
				this.smb.SetConnectParameters(uncPath.ServerName, parms);

				if (string.IsNullOrEmpty(uncPath.ShareName))
					throw new ArgumentException("The UNC path must include a share name");

				// Local NTFS mode uses admin-share-style UNC paths to keep provider/cmdlet UX consistent,
				// but must not attempt to create an SMB connection to the local machine. This allows
				// `New-PSDrive -PSProvider TBO.Smb2 -Root \\localhost\\C$` to work without network calls.
				if (OperatingSystem.IsWindows() && LocalNtfsUncPathMapper.IsLocalHost(uncPath.ServerName))
				{
					if (!LocalNtfsUncPathMapper.IsSupportedLocalAdminShare(uncPath))
						throw new NotSupportedException("Local-mode PSDrive roots must be a <DriveLetter>$ admin share (ex: \\\\localhost\\C$).");

					this.LogDiagnostic($"TBO: Creating local-mode PSDrive for '{drive.Root}' (bypassing SMB connect).");
					return new SmbShareDriveInfo(drive, this, uncPath, share: null);
				}

				var client = this.SmbClient;
				var share = client.GetShare(uncPath, cancellationToken).Result;
				try
				{
					this.smb.EnsureBackupIntentAccessAsync(uncPath, share, cancellationToken).GetAwaiter().GetResult();
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

			var uncPath = snapshotPath.ResolvedPath;
			if (string.IsNullOrEmpty(uncPath.ShareRelativePath))
				throw new NotSupportedException("New-Item requires a file or directory path, not a share root.");

			if (OperatingSystem.IsWindows() && LocalNtfsUncPathMapper.IsSupportedLocalAdminShare(uncPath))
			{
				this.BeginOperation(cancellationToken =>
				{
					cancellationToken.ThrowIfCancellationRequested();

					var newItemParams = this.DynamicParameters as SmbNewItemParams ?? GetNewItemParamsCore(itemTypeName) ?? new SmbNewFileItemParams();

					var localPath = LocalNtfsUncPathMapper.MapToLocalPath(uncPath);

					if (newItemParams is SmbNewFileItemParams)
					{
						this.LogDiagnostic($"TBO: Creating local NTFS file '{snapshotPath.OriginalPath}'.");
						LocalNtfsFileOperations.CreateEmptyFile(localPath, this.LogDiagnostic, this.LogWarning, cancellationToken);
						return;
					}

					if (newItemParams is SmbNewDirectoryItemParams)
					{
						this.LogDiagnostic($"TBO: Creating local NTFS directory '{snapshotPath.OriginalPath}'.");
						LocalNtfsFileOperations.CreateDirectory(localPath, this.LogDiagnostic, this.LogWarning, cancellationToken);
						return;
					}

					throw new NotSupportedException("Local-mode New-Item currently supports only File and Directory item types.");
				});

				return;
			}

			this.BeginOperation(cancellationToken =>
			{
				var newItemParams = this.DynamicParameters as SmbNewItemParams ?? new SmbNewFileItemParams();
				var file = newItemParams.Create(this.SmbClient, uncPath, cancellationToken).GetAwaiter().GetResult();
				try
				{
					// No output by default; provider engines typically query the created item separately.
				}
				finally
				{
					file.CloseAsync(cancellationToken).GetAwaiter().GetResult();
				}
			});
		}

		protected override bool IsItemContainer(string path)
		{
			if (!UncPath.TryParse(path, out var parsedPath))
				return false;

			var snapshotPath = ResolveSnapshotPath(parsedPath!);
			UncPath uncPath = snapshotPath.ResolvedPath;

			// Local NTFS mode treats \\localhost\<Drive>$ as a drive-backed share. Provider navigation must avoid SMB
			// entirely for these paths to ensure backup-intent semantics work without network calls.
				if (OperatingSystem.IsWindows() && LocalNtfsUncPathMapper.IsSupportedLocalAdminShare(uncPath))
				{
					if (string.IsNullOrEmpty(uncPath.ShareRelativePath))
						return true;

					return this.BeginOperation(cancellationToken =>
					{
						if (!TryGetLocalItemEntry(uncPath, snapshotPath.TimeWarpToken, cancellationToken, out var entry))
							return false;

						return 0 != (entry.FileAttributes & Winterop.FileAttributes.Directory);
					});
			}

			if (string.IsNullOrEmpty(uncPath.ShareRelativePath))
				return true;

			return this.BeginOperation(cancellationToken =>
			{
				var createInfo = SmbCreateInfoFactory.CreateOpenReadFileInfo(
					snapshotPath.TimeWarpToken,
					nonDirectory: false,
					openReparsePoint: false);

				using (var file = this.smb.SmbClient.CreateFileAsync(uncPath, createInfo, FileAccess.Read, cancellationToken).Result)
				{
					return file.IsDirectory;
				}
			});
		}

		protected override void GetItem(string path)
		{
			if (!UncPath.TryParse(path, out var parsedPath))
			{
				base.GetItem(path);
				return;
			}

			var snapshotPath = ResolveSnapshotPath(parsedPath!);
			UncPath uncPath = snapshotPath.ResolvedPath;

				if (!OperatingSystem.IsWindows() || !LocalNtfsUncPathMapper.IsSupportedLocalAdminShare(uncPath))
				{
					base.GetItem(path);
					return;
				}

				if (string.IsNullOrEmpty(uncPath.ShareRelativePath))
				{
					var entry = CreateLocalShareRootEntry(uncPath);
					var smbItem = new SmbItem(snapshotPath.OriginalPath, entry);
				this.WriteItemObject(smbItem, snapshotPath.OriginalPath.ToString(), isContainer: true);
				return;
			}

				this.BeginOperation(cancellationToken =>
				{
					if (!TryGetLocalItemEntry(uncPath, snapshotPath.TimeWarpToken, cancellationToken, out var entry))
						throw new ItemNotFoundException($"Cannot find path '{path}' because it does not exist.");

					var smbItem = new SmbItem(snapshotPath.OriginalPath, entry);
					this.WriteItemObject(smbItem, snapshotPath.OriginalPath.ToString(), 0 != (entry.FileAttributes & Winterop.FileAttributes.Directory));
				});
		}

		protected override void GetChildItems(string path, bool recurse)
		{
			// Provider engine behavior differs between `Get-ChildItem` and `Get-ChildItem -Depth`, so keep both
			// overrides aligned by funneling through the depth-aware implementation.
			GetChildItems(path, recurse, depth: uint.MaxValue);
		}

		protected override bool ConvertPath(string path, string filter, ref string updatedPath, ref string updatedFilter)
		{
			return base.ConvertPath(path, filter, ref updatedPath, ref updatedFilter);
		}

		protected override void GetChildItems(string path, bool recurse, uint depth)
		{
			var snapshotPath = ResolveSnapshotPath(path);
			UncPath uncPath = snapshotPath.ResolvedPath;

				if (OperatingSystem.IsWindows() && LocalNtfsUncPathMapper.IsSupportedLocalAdminShare(uncPath))
				{
					this.BeginOperation(cancellationToken =>
					{
						this.LogDiagnostic($"TBO: Enumerating local NTFS directory '{snapshotPath.OriginalPath}'.");

						var localFs = new LocalNtfsFileSystem(this.LogDiagnostic, this.LogWarning);
						using var dir = localFs.OpenDirectory(uncPath, snapshotPath.TimeWarpToken, cancellationToken);
						var entries = dir.QueryEntries("*", Smb2Directory.Smb2DirQueryOptions.None, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken);

						foreach (var entry in entries)
						{
						if (string.IsNullOrEmpty(entry.FileName))
							continue;
						if (entry.FileName is "." or "..")
							continue;

						UncPath itemPath = snapshotPath.OriginalPath.Append(entry.FileName);
						var smbItem = new SmbItem(itemPath, entry);
						this.WriteItemObject(smbItem, itemPath.ToString(), 0 != (entry.FileAttributes & Winterop.FileAttributes.Directory));
					}
				});

				return;
			}

			this.BeginOperation(cancellationToken =>
			{
				var createInfo = SmbCreateInfoFactory.CreateOpenDirectoryInfo(snapshotPath.TimeWarpToken);
				using (var dir = (Smb2Directory)this.smb.SmbClient.CreateFileAsync(uncPath, createInfo, FileAccess.Read, cancellationToken).Result)
				{
					bool includeRootReparseInfo = false;
					var connectParams = SmbConnectionParameters.ResolveOrDefault(this.smb, uncPath.ServerName);
					if (connectParams.IncludeRootReparseInfo != null)
						includeRootReparseInfo = connectParams.IncludeRootReparseInfo.Value;

					bool includeReparseInfo = !string.IsNullOrEmpty(uncPath.ShareRelativePath) || includeRootReparseInfo;

					if (!includeReparseInfo)
						this.LogDiagnostic($"Skipping reparse info for root enumeration on '{snapshotPath.OriginalPath}'.");

					var entries = dir.QueryDirAsync("*", Smb2Directory.Smb2DirQueryOptions.None, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken).GetAwaiter().GetResult();

					foreach (var entry in entries)
					{
						if (string.IsNullOrEmpty(entry.FileName))
							continue;
						if (entry.FileName is "." or "..")
							continue;
						UncPath itemPath = snapshotPath.OriginalPath.Append(entry.FileName);
						Winterop.ReparseTag? reparseTag = null;
						string? linkTarget = null;
						if (includeReparseInfo && 0 != (entry.FileAttributes & Winterop.FileAttributes.ReparsePoint))
						{
							if (TryReadReparseInfo(snapshotPath.ResolvedPath.Append(entry.FileName), snapshotPath.TimeWarpToken, cancellationToken, out var tag, out var target))
							{
								reparseTag = tag;
								linkTarget = target;
							}
						}
						var smbItem = new SmbItem(itemPath, entry, reparseTag, linkTarget);
						this.WriteItemObject(smbItem, itemPath.ToString(), 0 != (entry.FileAttributes & Winterop.FileAttributes.Directory));
					}
				}
			});
		}

		private static Smb2DirEntry CreateLocalShareRootEntry(UncPath uncPath)
		{
			// The provider renders items using SmbItem, which expects an Smb2DirEntry. Share roots are not
			// returned by directory enumeration, so we synthesize a minimal entry for `Get-Item \\localhost\\C$`.
			// This is local-only and intentionally does not attempt to resolve reparse tag/target metadata.
			DateTime utcNow = DateTime.UtcNow;

			return new Smb2DirEntry
			{
				FileName = uncPath.ShareName,
				RelativePath = string.Empty,
				CreationTime = utcNow,
				LastAccessTime = utcNow,
				LastWriteTime = utcNow,
				LastChangeTime = utcNow,
				Size = 0,
				SizeOnDisk = 0,
				FileAttributes = Winterop.FileAttributes.Directory,
				EaSize = 0,
			};
		}

			private bool TryGetLocalItemEntry(UncPath uncPath, DateTime? timeWarpToken, CancellationToken cancellationToken, out Smb2DirEntry entry)
			{
				entry = new Smb2DirEntry();

				var relativePath = uncPath.ShareRelativePath ?? string.Empty;
				relativePath = relativePath.Replace('/', '\\').TrimEnd('\\');
				if (string.IsNullOrEmpty(relativePath))
					return false;

				var name = Path.GetFileName(relativePath);
				if (string.IsNullOrEmpty(name))
					return false;

				var parentRelative = Path.GetDirectoryName(relativePath) ?? string.Empty;
				var parentPath = new UncPath(uncPath.ServerName, uncPath.Port, uncPath.ShareName, parentRelative);

				var localFs = new LocalNtfsFileSystem(this.LogDiagnostic, this.LogWarning);
				using var parentDir = localFs.OpenDirectory(parentPath, timeWarpToken, cancellationToken);
				var entries = parentDir.QueryEntries("*", Smb2Directory.Smb2DirQueryOptions.None, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken);
				foreach (var candidate in entries)
				{
					if (string.IsNullOrEmpty(candidate.FileName))
						continue;

					if (string.Equals(candidate.FileName, name, StringComparison.OrdinalIgnoreCase))
					{
						entry = candidate;
						return true;
					}
				}

				return false;
			}

		private bool TryReadReparseInfo(UncPath resolvedPath, DateTime? timeWarpToken, CancellationToken cancellationToken, out Winterop.ReparseTag? tag, out string? linkTarget)
		{
			tag = null;
			linkTarget = null;

			try
			{
				var createInfo = SmbCreateInfoFactory.CreateOpenReparseInfo(timeWarpToken);
				using var file = this.smb.SmbClient.CreateFileAsync(resolvedPath, createInfo, FileAccess.Read, cancellationToken).GetAwaiter().GetResult();

				var reparseInfo = file.GetReparseInfoAsync(cancellationToken).GetAwaiter().GetResult();
				tag = reparseInfo.Tag;
				if (reparseInfo is Winterop.SymbolicLinkInfo symlink)
					linkTarget = symlink.PrintName;
				else if (reparseInfo is Winterop.MountPointInfo mount)
					linkTarget = mount.PrintName;

				return true;
			}
			catch (Exception ex)
			{
				this.LogDiagnostic($"Reparse info probe failed for '{resolvedPath}': {ex.Message}");
				return false;
			}
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
			if (!UncPath.TryParse(path, out UncPath uncPath))
				return false;

			var snapshotPath = ResolveSnapshotPath(uncPath);
			uncPath = snapshotPath.ResolvedPath;

				if (OperatingSystem.IsWindows() && LocalNtfsUncPathMapper.IsSupportedLocalAdminShare(uncPath))
				{
					if (string.IsNullOrEmpty(uncPath.ShareRelativePath))
						return true;

					return this.BeginOperation(cancellationToken =>
					{
						try
						{
							return TryGetLocalItemEntry(uncPath, snapshotPath.TimeWarpToken, cancellationToken, out _);
						}
						catch
						{
							return false;
						}
				});
			}

			if (string.IsNullOrEmpty(uncPath.ShareRelativePath))
				return true;

			return this.BeginOperation(cancellationToken =>
			{
				try
				{
					var createInfo = SmbCreateInfoFactory.CreateOpenReadFileInfo(
						snapshotPath.TimeWarpToken,
						nonDirectory: false,
						openReparsePoint: true);

					using (this.SmbClient.CreateFileAsync(uncPath, createInfo, FileAccess.Read, cancellationToken).Result)
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
			var snapshotPath = ResolveSnapshotPath(path);
			if (snapshotPath.HasTimeWarpToken)
				throw new NotSupportedException("Snapshot paths are read-only.");

			UncPath uncPath = snapshotPath.ResolvedPath;
			if (string.IsNullOrEmpty(uncPath.ShareRelativePath))
				throw new NotSupportedException("Get-Content and Set-Content require a file path, not a share root.");

			if (OperatingSystem.IsWindows() && LocalNtfsUncPathMapper.IsSupportedLocalAdminShare(uncPath))
			{
				this.BeginOperation(cancellationToken =>
				{
					cancellationToken.ThrowIfCancellationRequested();

					this.LogDiagnostic($"TBO: Clearing local NTFS content '{snapshotPath.OriginalPath}'.");

					var localPath = LocalNtfsUncPathMapper.MapToLocalPath(uncPath);

					var access =
						LocalNtfsFileAccess.WriteDataOrAddFile |
						LocalNtfsFileAccess.Synchronize;

					using var stream = LocalNtfsCreateFile.OpenFileStream(
						localPath,
						access,
						FileMode.OpenOrCreate,
						FileAccess.Write,
						share: FileShare.ReadWrite | FileShare.Delete,
						flags: LocalNtfsOpenFlags.None,
						includeSecurityPrivilege: false,
						logDiagnostic: this.LogDiagnostic,
						logWarning: this.LogWarning);

					stream.SetLength(0);
				});

				return;
			}

			this.BeginOperation(cancellationToken =>
			{
				var createInfo = SmbCreateInfoFactory.CreateContentWriteInfo(
					Smb2CreateDisposition.OverwriteIf,
					snapshotPath.TimeWarpToken);
				using var file = (Smb2OpenFile)this.smb.SmbClient.CreateFileAsync(uncPath, createInfo, FileAccess.ReadWrite, cancellationToken).Result;

				using var stream = file.GetStream(true);
				stream.SetLength(0);
			});
		}

		public object ClearContentDynamicParameters(string path)
		{
			return null;
		}

		public IContentReader GetContentReader(string path)
		{
			var snapshotPath = ResolveSnapshotPath(path);
			UncPath uncPath = snapshotPath.ResolvedPath;
			if (string.IsNullOrEmpty(uncPath.ShareRelativePath))
				throw new NotSupportedException("Get-Content requires a file path, not a share root.");

				if (OperatingSystem.IsWindows() && LocalNtfsUncPathMapper.IsSupportedLocalAdminShare(uncPath))
				{
					return this.BeginOperation(cancellationToken =>
					{
						cancellationToken.ThrowIfCancellationRequested();

						this.LogDiagnostic($"TBO: Opening local NTFS content reader for '{snapshotPath.OriginalPath}'.");

					var parms = this.DynamicParameters as SmbGetContentParams;
					var encoding = parms?.Encoding ?? Encoding.UTF8;
					var raw = parms?.Raw.IsPresent ?? false;

						var localPath = LocalNtfsUncPathMapper.MapToLocalPath(uncPath, snapshotPath.TimeWarpToken, this.LogDiagnostic, this.LogWarning);
						var access =
							LocalNtfsFileAccess.ReadDataOrListDirectory |
							LocalNtfsFileAccess.ReadAttributes |
							LocalNtfsFileAccess.ReadExtendedAttributes |
						LocalNtfsFileAccess.Synchronize;

					var stream = LocalNtfsCreateFile.OpenFileStream(
						localPath,
						access,
						FileMode.Open,
						FileAccess.Read,
						share: FileShare.ReadWrite | FileShare.Delete,
						flags: LocalNtfsOpenFlags.None,
						includeSecurityPrivilege: false,
						logDiagnostic: this.LogDiagnostic,
						logWarning: this.LogWarning);

					return (IContentReader)new SmbContentReader(stream, encoding, raw);
				});
			}

			return this.BeginOperation(cancellationToken =>
			{
				var parms = this.DynamicParameters as SmbGetContentParams;
				var encoding = parms?.Encoding ?? Encoding.UTF8;
				var raw = parms?.Raw.IsPresent ?? false;

				var createInfo = SmbCreateInfoFactory.CreateOpenReadFileInfo(
					snapshotPath.TimeWarpToken,
					nonDirectory: true,
					openReparsePoint: false);
				var file = (Smb2OpenFile)this.smb.SmbClient.CreateFileAsync(uncPath, createInfo, FileAccess.Read, cancellationToken).Result;
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
			var snapshotPath = ResolveSnapshotPath(path);
			if (snapshotPath.HasTimeWarpToken)
				throw new NotSupportedException("Snapshot paths are read-only.");

			UncPath uncPath = snapshotPath.ResolvedPath;
			if (string.IsNullOrEmpty(uncPath.ShareRelativePath))
				throw new NotSupportedException("Set-Content and Add-Content require a file path, not a share root.");

			if (OperatingSystem.IsWindows() && LocalNtfsUncPathMapper.IsSupportedLocalAdminShare(uncPath))
			{
				return this.BeginOperation(cancellationToken =>
				{
					cancellationToken.ThrowIfCancellationRequested();

					var parms = this.DynamicParameters as SmbSetContentParams ?? new SmbSetContentParams();
					var encoding = parms.Encoding ?? Encoding.UTF8;
					var invocation = GetProviderInvocationInfo(this);
					var commandName = invocation?.MyCommand?.Name;
					var isAddContent = string.Equals(commandName, "Add-Content", StringComparison.OrdinalIgnoreCase);
					var force = GetContextSwitch(this, "Force");
					var noClobber = invocation?.BoundParameters != null
						&& invocation.BoundParameters.ContainsKey("NoClobber")
						&& invocation.BoundParameters["NoClobber"] is true;

					if (force)
						noClobber = false;

					var mode = isAddContent
						? FileMode.OpenOrCreate
						: noClobber
							? FileMode.CreateNew
							: FileMode.Create;

					this.LogDiagnostic($"TBO: Opening local NTFS content writer for '{snapshotPath.OriginalPath}' (mode={mode}).");

					var localPath = LocalNtfsUncPathMapper.MapToLocalPath(uncPath);
					var access =
						LocalNtfsFileAccess.WriteDataOrAddFile |
						LocalNtfsFileAccess.AppendDataOrAddSubdirectory |
						LocalNtfsFileAccess.Synchronize;

					var stream = LocalNtfsCreateFile.OpenFileStream(
						localPath,
						access,
						mode,
						FileAccess.Write,
						share: FileShare.ReadWrite | FileShare.Delete,
						flags: LocalNtfsOpenFlags.None,
						includeSecurityPrivilege: false,
						logDiagnostic: this.LogDiagnostic,
						logWarning: this.LogWarning);

					if (isAddContent)
						stream.Seek(0, SeekOrigin.End);

					return (IContentWriter)new SmbContentWriter(stream, encoding, parms.NoNewline.IsPresent);
				});
			}

			return this.BeginOperation(cancellationToken =>
			{
				var parms = this.DynamicParameters as SmbSetContentParams ?? new SmbSetContentParams();
				var encoding = parms.Encoding ?? Encoding.UTF8;
				var invocation = GetProviderInvocationInfo(this);
				var commandName = invocation?.MyCommand?.Name;
				var isAddContent = string.Equals(commandName, "Add-Content", StringComparison.OrdinalIgnoreCase);
				var force = GetContextSwitch(this, "Force");
				var noClobber = invocation?.BoundParameters != null
					&& invocation.BoundParameters.ContainsKey("NoClobber")
					&& invocation.BoundParameters["NoClobber"] is true;

				if (force)
					noClobber = false;

				var createDisposition = isAddContent
					? Smb2CreateDisposition.OpenIf
					: noClobber
						? Smb2CreateDisposition.Create
						: Smb2CreateDisposition.OverwriteIf;

				var createInfo = SmbCreateInfoFactory.CreateContentWriteInfo(
					createDisposition,
					snapshotPath.TimeWarpToken);
				var file = (Smb2OpenFile)this.smb.SmbClient.CreateFileAsync(uncPath, createInfo, FileAccess.ReadWrite, cancellationToken).Result;

				var stream = file.GetStream(true);
				if (isAddContent)
					stream.Seek(0, SeekOrigin.End);

				return (IContentWriter)new SmbContentWriter(stream, encoding, parms.NoNewline.IsPresent);
			});
		}

		public object GetContentWriterDynamicParameters(string path)
		{
			return new SmbSetContentParams();
		}

		private static InvocationInfo? GetProviderInvocationInfo(CmdletProvider provider)
		{
			var context = GetProviderContext(provider);
			if (context == null)
				return null;

			var prop = context.GetType().GetProperty("MyInvocation", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
			return prop?.GetValue(context) as InvocationInfo;
		}

		private static bool GetContextSwitch(CmdletProvider provider, string name)
		{
			var context = GetProviderContext(provider);
			if (context == null)
				return false;

			var prop = context.GetType().GetProperty(name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
			if (prop == null || prop.PropertyType != typeof(bool))
				return false;

			return prop.GetValue(context) is bool value && value;
		}

		private static object? GetProviderContext(CmdletProvider provider)
		{
			var prop = typeof(CmdletProvider).GetProperty("Context", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
			return prop?.GetValue(provider);
		}
	}

	public partial class SmbProviderInfo : ProviderInfo, ISmb2TraceCallback, ISmbProviderInfo
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

			var directSocketService = new PlatformSocketService(this, null);
			var socketService = new TboProxySocketService(this, directSocketService);
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
				this.InvalidateRegistrySessions(null, RegistrySessionInvalidationReason.OptionsChanged);
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

			var priorParms = this.GetConnectParametersFor(serverName, false) ?? this.DefaultConnectParameters;
			var priorFingerprint = BuildRegistrySessionFingerprint(priorParms);
			var newFingerprint = BuildRegistrySessionFingerprint(parameters);

			lock (this._connectParams)
			{
				this._connectParams[serverName] = parameters;
			}

			if (!string.Equals(priorFingerprint, newFingerprint, StringComparison.Ordinal))
				this.InvalidateRegistrySessions(serverName, RegistrySessionInvalidationReason.OptionsChanged);
		}
		#endregion

		private static ILog? CreateLocalLog(out TextWriter? writer)
		{
			writer = null;

			var setting = Environment.GetEnvironmentVariable("TITANIS_TBO_LOG");
			if (!TryParseLogSetting(setting, out var path, out var level))
				return null;

			var dir = Path.GetDirectoryName(path);
			if (!string.IsNullOrWhiteSpace(dir))
				Directory.CreateDirectory(dir);

			writer = new StreamWriter(new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
			{
				AutoFlush = true
			};

			var log = new TextWriterLog(writer)
			{
				LogLevel = level,
				Format = LogFormat.TextWithTimestamp
			};
			log.WriteInfo($"TBO logging enabled: {path} (level: {level})");
			return log;
		}

		private static bool TryParseLogSetting(string? setting, out string path, out LogMessageSeverity level)
		{
			path = string.Empty;
			level = LogMessageSeverity.Info;

			if (string.IsNullOrWhiteSpace(setting))
				return false;

			var trimmed = setting.Trim();
			if (IsEnabledLogToken(trimmed))
			{
				path = GetDefaultLogPath();
				return true;
			}

			var separatorIndex = trimmed.LastIndexOf(';');
			if (separatorIndex >= 0)
			{
				var pathToken = trimmed.Substring(0, separatorIndex).Trim();
				var levelToken = trimmed.Substring(separatorIndex + 1).Trim();
				path = string.IsNullOrWhiteSpace(pathToken) ? GetDefaultLogPath() : pathToken;
				level = ParseLogLevelOrDefault(levelToken);
				return true;
			}

			if (TryParseLogLevel(trimmed, out var parsedLevel))
			{
				path = GetDefaultLogPath();
				level = parsedLevel;
				return true;
			}

			path = trimmed;
			return true;
		}

		private static bool IsEnabledLogToken(string value)
		{
			return value.Equals("1", StringComparison.OrdinalIgnoreCase)
				|| value.Equals("true", StringComparison.OrdinalIgnoreCase)
				|| value.Equals("yes", StringComparison.OrdinalIgnoreCase);
		}

		private static string GetDefaultLogPath()
		{
			return Path.Combine(Path.GetTempPath(), "Titanis.TBO.Smb2.log");
		}

		private static LogMessageSeverity ParseLogLevelOrDefault(string? value)
		{
			return TryParseLogLevel(value, out var parsed) ? parsed : LogMessageSeverity.Info;
		}

		private static bool TryParseLogLevel(string? value, out LogMessageSeverity level)
		{
			level = LogMessageSeverity.Info;
			if (string.IsNullOrWhiteSpace(value))
				return false;

			return Enum.TryParse(value.Trim(), true, out level);
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

			var parms = SmbConnectionParameters.ResolveOrDefault(this, serverName);

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
					effectiveUser ??= ticket.ClientName;
					authRealm ??= ticket.ClientRealm;
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
							if ((authUser == null || string.Equals(authUser, tgtTicket.ClientName, StringComparison.OrdinalIgnoreCase))
								&& (authRealm == null || string.Equals(authRealm, tgtTicket.ClientRealm, StringComparison.OrdinalIgnoreCase)))
							{
								authUser ??= tgtTicket.ClientName;
								authRealm ??= tgtTicket.ClientRealm;
								krb.ImportTicket(tgtTicket);
							}
						}
					}
				}

				KerberosCredential? cred = null;
				if (!string.IsNullOrEmpty(authUser) && !string.IsNullOrEmpty(authRealm))
				{
					var upn = new UserPrincipalName(authUser, authRealm);
					if (parms.Password != null)
						cred = new KerberosPasswordCredential(upn, parms.Password);
					else if (parms.NtlmHash != null)
						cred = new KerberosKeyCredential(upn, EType.Rc4Hmac, parms.NtlmHash.NtHash);
					else if (parms.AesKey != null)
						cred = new KerberosKeyCredential(upn, parms.AesKey.Bytes.Length switch
						{
							(128 / 8) => EType.Aes128CtsHmacSha1_96,
							(256 / 8) => EType.Aes256CtsHmacSha1_96,
							_ => throw new ArgumentException("The AES key is not the correct size for AES 128 or AES 256.")
						}, parms.AesKey.Bytes);
					else if (parms.DesKey != null)
						cred = new KerberosKeyCredential(upn, EType.DesCbcMd5, parms.DesKey.Bytes);
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
					cred ??= new KerberosNullCredential(new UserPrincipalName(authUser ?? ticket.ClientName ?? string.Empty, authRealm ?? ticket.ServiceRealm ?? ticket.ClientRealm));
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
					ChannelBinding = null
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

			this.LogWarning(v);
		}

		private static bool CheckMatchingTicket(ServicePrincipalName targetSpn, TicketInfo ticket, ref string? userName, ref string? userRealm)
		{
			if (!ticket.TargetSpn.Equals(targetSpn))
				return false;

			if (
				(userName == null || string.Equals(userName, ticket.ClientName, StringComparison.OrdinalIgnoreCase))
				&& (userRealm == null || string.Equals(userRealm, ticket.ClientRealm, StringComparison.OrdinalIgnoreCase))
				)
			{
				userName ??= ticket.ClientName;
				userRealm ??= ticket.ClientRealm;
				return true;
			}

			return false;
		}
	}

	partial class SmbProviderInfo : INameResolverService
	{
		public Task<IPAddress[]> ResolveAsync(string hostName, CancellationToken cancellationToken)
		{
			var parms = SmbConnectionParameters.TryGetServerSpecific(this, hostName);
			if (!string.IsNullOrWhiteSpace(parms?.HostName))
				hostName = parms.HostName;

			return PlatformNameResolverService.ResolveAsync(hostName, this.DefaultConnectParameters.NameResolveOptions.Value, null, cancellationToken);
		}
	}
	partial class SmbProviderInfo : ISmbOptionsService
	{
		public Smb2ConnectionOptions? GetConnectionOptionsFor(string serverName)
		{
			var parms = SmbConnectionParameters.ResolveOrDefault(this, serverName);
			var options = parms.ToConnectionOptions();
			if (s_forceZeroCreditFallback.Value)
				options.AllowZeroCreditFallback = true;
			return options;
		}
	}
}
