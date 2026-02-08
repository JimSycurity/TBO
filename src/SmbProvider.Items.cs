using System;
using System.IO;
using System.Management.Automation;
using Titanis.Net;
using Titanis.Smb2;
using Titanis.Winterop.Security;
using Smb2AccessRights = Titanis.Smb2.Smb2FileAccessRights;
using Winterop = Titanis.Winterop;
using Titanis.IO;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public partial class SmbProvider
	{
		protected override void CopyItem(string path, string copyPath, bool recurse)
		{
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("Path must be provided.", nameof(path));
			if (string.IsNullOrWhiteSpace(copyPath))
				throw new ArgumentException("Destination must be provided.", nameof(copyPath));
			if (recurse)
				throw new NotSupportedException("Directory copy is not supported.");

			var snapshotPath = ResolveSnapshotPath(path);
			UncPath sourcePath = snapshotPath.ResolvedPath;
			if (string.IsNullOrEmpty(sourcePath.ShareRelativePath))
				throw new ArgumentException("Source path must include a file name.", nameof(path));

			ProviderInfo? providerInfo;
			PSDriveInfo? driveInfo;
			string destinationPath;
			try
			{
				destinationPath = this.SessionState.Path.GetUnresolvedProviderPathFromPSPath(copyPath, out providerInfo, out driveInfo);
			}
			catch (Exception ex)
			{
				throw new ArgumentException($"Destination path could not be resolved: {copyPath}", nameof(copyPath), ex);
			}

			if (providerInfo == null || !providerInfo.Name.Equals("FileSystem", StringComparison.OrdinalIgnoreCase))
				throw new NotSupportedException("Copy-Item from TBO.Smb2 only supports FileSystem destinations.");

			var fileName = Path.GetFileName(sourcePath.ShareRelativePath ?? string.Empty);
			if (string.IsNullOrEmpty(fileName))
				throw new IOException($"Source path '{sourcePath}' does not specify a file name.");
			if (Directory.Exists(destinationPath))
				destinationPath = Path.Combine(destinationPath, fileName);
			if (Directory.Exists(destinationPath))
				throw new IOException($"Destination path '{destinationPath}' is a directory.");

			this.BeginOperation(cancellationToken =>
			{
				using var file = (Smb2OpenFile)this.smb.SmbClient.CreateFileAsync(sourcePath, new Smb2CreateInfo
				{
					CreateDisposition = Smb2CreateDisposition.Open,
					DesiredAccess = (uint)Smb2AccessRights.DefaultOpenReadAccess,
					ShareAccess = Smb2ShareAccess.Read,
					ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
					CreateOptions = Smb2FileCreateOptions.NonDirectory
						| Smb2FileCreateOptions.SynchronousIoNonalert
						| Smb2FileCreateOptions.OpenForBackupIntent,
					FileAttributes = Winterop.FileAttributes.Normal,
					TimeWarpToken = snapshotPath.TimeWarpToken
				}, FileAccess.Read, cancellationToken).Result;

				if (file.IsDirectory)
					throw new IOException($"Source path '{sourcePath}' is a directory.");

				using var sourceStream = file.GetStream(false);
				using var destStream = new FileStream(destinationPath, FileMode.Create, FileAccess.Write, FileShare.Read, Smb2Client.DefaultChunkSize, FileOptions.SequentialScan);
				sourceStream.CopyToAsync2(destStream, Smb2Client.DefaultChunkSize, cancellationToken).GetAwaiter().GetResult();
			});
		}

		protected override void RemoveItem(string path, bool recurse)
		{
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("Path must be provided.", nameof(path));

			var snapshotPath = ResolveSnapshotPath(path);
			if (snapshotPath.HasTimeWarpToken)
				throw new NotSupportedException("Snapshot paths are read-only.");

			UncPath uncPath = snapshotPath.ResolvedPath;
			if (string.IsNullOrEmpty(uncPath.ShareRelativePath))
				throw new ArgumentException("Path must include a file or directory name.", nameof(path));

			if (OperatingSystem.IsWindows() && LocalNtfsUncPathMapper.IsSupportedLocalAdminShare(uncPath))
			{
				this.BeginOperation(cancellationToken =>
				{
					RemoveLocalItemCore(snapshotPath.OriginalPath.ToString(), uncPath, recurse, cancellationToken);
				});
				return;
			}

			this.BeginOperation(cancellationToken =>
			{
				RemoveItemCore(uncPath, recurse, cancellationToken);
			});
		}

		protected override bool HasChildItems(string path)
		{
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("Path must be provided.", nameof(path));

			var snapshotPath = ResolveSnapshotPath(path);
			UncPath uncPath = snapshotPath.ResolvedPath;

			return this.BeginOperation(cancellationToken =>
			{
				Smb2OpenFileObjectBase? file = null;
				try
				{
					file = this.smb.SmbClient.CreateFileAsync(uncPath, new Smb2CreateInfo
					{
						CreateDisposition = Smb2CreateDisposition.Open,
						Priority = Smb2Priority.OpenDir,
						DesiredAccess = (uint)Smb2AccessRights.DefaultOpenDirAccess,
						ShareAccess = Smb2ShareAccess.DefaultDirShare,
						FileAttributes = Winterop.FileAttributes.None,
						CreateOptions = Smb2FileCreateOptions.Directory
							| Smb2FileCreateOptions.SynchronousIoNonalert
							| Smb2FileCreateOptions.OpenReparsePoint
							| Smb2FileCreateOptions.OpenForBackupIntent,
						ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
						RequestMaximalAccess = true,
						QueryOnDiskId = true,
						TimeWarpToken = snapshotPath.TimeWarpToken,
						OplockLevel = Smb2OplockLevel.None
					}, FileAccess.Read, cancellationToken).GetAwaiter().GetResult();

					if (!file.IsDirectory)
						return false;

					if (0 != (file.FileAttributes & Winterop.FileAttributes.ReparsePoint))
						return false;

					var dir = (Smb2Directory)file;
					foreach (var entry in dir.QueryDirAsync("*", Smb2Directory.Smb2DirQueryOptions.None, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken).GetAwaiter().GetResult())
					{
						if (string.IsNullOrEmpty(entry.FileName))
							continue;
						if (entry.FileName is "." or "..")
							continue;
						return true;
					}
					return false;
				}
				catch (Winterop.NtstatusException ex) when (ex.StatusCode == Winterop.Ntstatus.STATUS_NOT_A_DIRECTORY)
				{
					return false;
				}
				finally
				{
					if (file != null)
						file.CloseAsync(cancellationToken).GetAwaiter().GetResult();
				}
			});
		}

		private void RemoveItemCore(UncPath uncPath, bool recurse, System.Threading.CancellationToken cancellationToken)
		{
			Smb2OpenFileObjectBase? file = null;
			try
			{
				file = this.smb.SmbClient.CreateFileAsync(uncPath, new Smb2CreateInfo
				{
					CreateDisposition = Smb2CreateDisposition.Open,
					DesiredAccess = (uint)Smb2AccessRights.ReadAttributes,
					ShareAccess = Smb2ShareAccess.ReadWriteDelete,
					FileAttributes = Winterop.FileAttributes.Normal,
					CreateOptions = Smb2FileCreateOptions.SynchronousIoNonalert
						| Smb2FileCreateOptions.OpenReparsePoint
						| Smb2FileCreateOptions.OpenForBackupIntent,
					ImpersonationLevel = Smb2ImpersonationLevel.Impersonation
				}, FileAccess.Read, cancellationToken).Result;

				if (!file.IsDirectory)
				{
					this.smb.SmbClient.DeleteFileAsync(uncPath, cancellationToken).GetAwaiter().GetResult();
					return;
				}
			}
			finally
			{
				if (file != null)
					file.CloseAsync(cancellationToken).GetAwaiter().GetResult();
			}

			if (recurse)
			{
				RemoveDirectoryRecursive(uncPath, cancellationToken);
				return;
			}

			this.smb.SmbClient.RemoveDirectoryAsync(uncPath, cancellationToken).GetAwaiter().GetResult();
		}

		private void RemoveDirectoryRecursive(UncPath directoryPath, System.Threading.CancellationToken cancellationToken)
		{
			Smb2Directory? dir = null;
			try
			{
				dir = (Smb2Directory)this.smb.SmbClient.CreateFileAsync(directoryPath, new Smb2CreateInfo
				{
					CreateDisposition = Smb2CreateDisposition.Open,
					Priority = Smb2Priority.OpenDir,
					DesiredAccess = (uint)Smb2AccessRights.DefaultOpenDirAccess,
					ShareAccess = Smb2ShareAccess.DefaultDirShare,
					FileAttributes = Winterop.FileAttributes.None,
					CreateOptions = Smb2FileCreateOptions.Directory
						| Smb2FileCreateOptions.SynchronousIoNonalert
						| Smb2FileCreateOptions.OpenReparsePoint
						| Smb2FileCreateOptions.OpenForBackupIntent,
					ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
					RequestMaximalAccess = true,
					QueryOnDiskId = true,
					OplockLevel = Smb2OplockLevel.None
				}, FileAccess.Read, cancellationToken).Result;

				foreach (var entry in dir.QueryDirAsync("*", Smb2Directory.Smb2DirQueryOptions.QueryReparseInfo, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken).Result)
				{
					if (entry.FileName is "." or "..")
						continue;

					var childPath = directoryPath.Append(entry.FileName);
					bool isDirectory = 0 != (entry.FileAttributes & Winterop.FileAttributes.Directory);
					bool isReparse = 0 != (entry.FileAttributes & Winterop.FileAttributes.ReparsePoint);

					if (isDirectory && !isReparse)
					{
						RemoveDirectoryRecursive(childPath, cancellationToken);
						continue;
					}

					if (isDirectory)
						this.smb.SmbClient.RemoveDirectoryAsync(childPath, cancellationToken).GetAwaiter().GetResult();
					else
						this.smb.SmbClient.DeleteFileAsync(childPath, cancellationToken).GetAwaiter().GetResult();
				}
			}
			finally
			{
				if (dir != null)
					dir.CloseAsync(cancellationToken).GetAwaiter().GetResult();
			}

			this.smb.SmbClient.RemoveDirectoryAsync(directoryPath, cancellationToken).GetAwaiter().GetResult();
		}

		private void RemoveLocalItemCore(string originalPath, UncPath uncPath, bool recurse, System.Threading.CancellationToken cancellationToken)
		{
			cancellationToken.ThrowIfCancellationRequested();

			this.LogDiagnostic($"TBO: Removing local NTFS item '{originalPath}' (recurse={recurse}).");

			if (!TryGetLocalItemEntry(uncPath, cancellationToken, out var entry))
				throw new ItemNotFoundException($"Cannot find path '{originalPath}' because it does not exist.");

			bool isDirectory = 0 != (entry.FileAttributes & Winterop.FileAttributes.Directory);
			bool isReparse = 0 != (entry.FileAttributes & Winterop.FileAttributes.ReparsePoint);

			var localPath = LocalNtfsUncPathMapper.MapToLocalPath(uncPath);

			if (!isDirectory)
			{
				LocalNtfsFileOperations.DeleteFile(localPath, openReparsePoint: true, this.LogDiagnostic, this.LogWarning, cancellationToken);
				return;
			}

			if (recurse && !isReparse)
			{
				RemoveLocalDirectoryRecursive(originalPath, uncPath, cancellationToken);
				return;
			}

			LocalNtfsFileOperations.DeleteDirectory(localPath, openReparsePoint: true, this.LogDiagnostic, this.LogWarning, cancellationToken);
		}

		private void RemoveLocalDirectoryRecursive(string originalPath, UncPath directoryPath, System.Threading.CancellationToken cancellationToken)
		{
			cancellationToken.ThrowIfCancellationRequested();

			this.LogDiagnostic($"TBO: Recursively removing local NTFS directory '{originalPath}'.");

			var localFs = new LocalNtfsFileSystem(this.LogDiagnostic, this.LogWarning);
			using var dir = localFs.OpenDirectory(directoryPath, cancellationToken);
			var entries = dir.QueryEntries("*", Smb2Directory.Smb2DirQueryOptions.QueryReparseInfo, SecurityInfo.None, Smb2Directory.DefaultQueryBufferSize, cancellationToken);

			foreach (var entry in entries)
			{
				cancellationToken.ThrowIfCancellationRequested();

				if (entry.FileName is "." or "..")
					continue;

				var childPath = directoryPath.Append(entry.FileName);
				bool isDirectory = 0 != (entry.FileAttributes & Winterop.FileAttributes.Directory);
				bool isReparse = 0 != (entry.FileAttributes & Winterop.FileAttributes.ReparsePoint);

				if (isDirectory && !isReparse)
				{
					RemoveLocalDirectoryRecursive(childPath.ToString(), childPath, cancellationToken);
					continue;
				}

				var childLocalPath = LocalNtfsUncPathMapper.MapToLocalPath(childPath);

				if (isDirectory)
					LocalNtfsFileOperations.DeleteDirectory(childLocalPath, openReparsePoint: true, this.LogDiagnostic, this.LogWarning, cancellationToken);
				else
					LocalNtfsFileOperations.DeleteFile(childLocalPath, openReparsePoint: true, this.LogDiagnostic, this.LogWarning, cancellationToken);
			}

			var localPath = LocalNtfsUncPathMapper.MapToLocalPath(directoryPath);
			LocalNtfsFileOperations.DeleteDirectory(localPath, openReparsePoint: true, this.LogDiagnostic, this.LogWarning, cancellationToken);
		}
	}
}
