using System;
using System.IO;
using System.Management.Automation;
using System.Threading;
using System.Threading.Tasks;
using Titanis.IO;
using Titanis.Net;
using Titanis.Smb2;
using Titanis.Winterop.Security;
using Smb2AccessRights = Titanis.Smb2.Smb2FileAccessRights;
using Smb2FileBasicInfo = Titanis.Smb2.Pdus.FileBasicInfo;
using Winterop = Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
[Cmdlet(VerbsCommon.Copy, "TBOSmbItem", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.Medium)]
public sealed class CopyTBOSmbItem : SmbCmdlet
{
		[Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
		public string Source { get; set; } = string.Empty;

		[Parameter(Mandatory = true, Position = 1, ValueFromPipelineByPropertyName = true)]
		public string Destination { get; set; } = string.Empty;

		[Parameter]
		[Alias("Overwrite")]
		public SwitchParameter Force { get; set; }

		[Parameter]
		public SwitchParameter CreateDirectories { get; set; }

		[Parameter]
		public SwitchParameter PreserveTimestamps { get; set; }

		[Parameter]
		public SwitchParameter PreserveSecurityDescriptor { get; set; }

		[Parameter]
		public int ChunkSize { get; set; } = Smb2Client.DefaultChunkSize;

		private CancellationTokenSource? _cancelSource;

		protected override void ProcessRecord(SmbProviderInfo smb)
		{
			this._cancelSource ??= new CancellationTokenSource();
			CopyAsync(smb, this._cancelSource.Token).ConfigureAwait(false).GetAwaiter().GetResult();
		}

		protected override void StopProcessing()
		{
			this._cancelSource?.Cancel();
			base.StopProcessing();
		}

		private async Task CopyAsync(SmbProviderInfo smb, CancellationToken cancellationToken)
		{
			var source = ResolvePath(this.Source, nameof(Source));
			var destination = ResolvePath(this.Destination, nameof(Destination));

			if (source.Kind == PathKind.Local && destination.Kind == PathKind.Local)
				throw new ArgumentException("At least one path must be a UNC path or a TBO.Smb2 PSDrive path.");
			if (destination.Kind == PathKind.Smb && destination.HasTimeWarpToken)
				throw new NotSupportedException("Snapshot paths are read-only.");
			if (this.PreserveSecurityDescriptor.IsPresent && (source.Kind == PathKind.Local || destination.Kind == PathKind.Local))
				throw new NotSupportedException("PreserveSecurityDescriptor is only supported for SMB-to-SMB copies.");

			var smbClient = smb.SmbClient;

			if (source.Kind == PathKind.Smb && destination.Kind == PathKind.Smb)
			{
				await CopySmbToSmbAsync(smbClient, source.SmbPath!, source.TimeWarpToken, destination.SmbPath!, cancellationToken).ConfigureAwait(false);
				return;
			}

			if (source.Kind == PathKind.Smb)
			{
				await CopySmbToLocalAsync(smbClient, source.SmbPath!, source.TimeWarpToken, destination.LocalPath!, cancellationToken).ConfigureAwait(false);
				return;
			}

			if (destination.HasTimeWarpToken)
				throw new NotSupportedException("Snapshot paths are read-only.");

			await CopyLocalToSmbAsync(smbClient, source.LocalPath!, destination.SmbPath!, cancellationToken).ConfigureAwait(false);
		}

	private async Task CopySmbToSmbAsync(
		Smb2Client smbClient,
		UncPath sourcePath,
		DateTime? sourceTimeWarpToken,
		UncPath destinationPath,
		CancellationToken cancellationToken)
	{
			if (string.IsNullOrEmpty(sourcePath.ShareRelativePath))
				throw new ArgumentException($"Source path must include a file name: {sourcePath}", nameof(Source));

			Smb2OpenFile? sourceFile = null;
			Smb2OpenFile? destFile = null;
			try
			{
				sourceFile = await OpenFileReadAsync(smbClient, sourcePath, sourceTimeWarpToken, cancellationToken).ConfigureAwait(false);
				if (sourceFile.IsDirectory)
					throw new IOException($"Source path '{sourcePath}' is a directory. Copy-TBOSmbItem supports files only.");

				var resolvedDest = await ResolveDestinationAsync(smbClient, sourcePath, destinationPath, cancellationToken).ConfigureAwait(false);
				destinationPath = resolvedDest.Path;

				if (resolvedDest.Exists && !this.Force.IsPresent)
					throw new IOException($"The file '{destinationPath}' already exists.");

				if (!ShouldProcessCopy(sourcePath.ToString(), destinationPath.ToString()))
					return;

				if (this.CreateDirectories.IsPresent)
					await EnsureRemoteDirectoryAsync(smbClient, destinationPath.GetDirectoryPath(), cancellationToken).ConfigureAwait(false);

				Smb2FileBasicInfo? sourceBasicInfo = null;
				if (this.PreserveTimestamps.IsPresent)
					sourceBasicInfo = await sourceFile.GetBasicInfoAsync(cancellationToken).ConfigureAwait(false);

				SecurityDescriptor? sourceSecurityDescriptor = null;
				if (this.PreserveSecurityDescriptor.IsPresent)
				{
					sourceSecurityDescriptor = await sourceFile.GetSecurityAsync(
						SecurityInfo.Owner | SecurityInfo.Group | SecurityInfo.Dacl | SecurityInfo.Sacl,
						8192,
						cancellationToken).ConfigureAwait(false);
				}

				var createInfo = new Smb2CreateInfo
				{
					CreateDisposition = GetCreateDisposition(resolvedDest.Exists, this.PreserveSecurityDescriptor.IsPresent),
					DesiredAccess = (uint)Smb2AccessRights.DefaultCreateAccess,
					ShareAccess = Smb2ShareAccess.ReadWrite,
					ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
					CreateOptions = Smb2FileCreateOptions.NonDirectory | Smb2FileCreateOptions.SynchronousIoNonalert,
					FileAttributes = Winterop.FileAttributes.Normal
				};

				if (sourceSecurityDescriptor != null)
					createInfo.SecurityDescriptor = sourceSecurityDescriptor.ToByteArray();

				destFile = (Smb2OpenFile)await smbClient.CreateFileAsync(
					destinationPath,
					createInfo,
					FileAccess.ReadWrite,
					cancellationToken).ConfigureAwait(false);

				if (sourceFile.Length > 0)
					await destFile.SetLengthAsync(sourceFile.Length, cancellationToken).ConfigureAwait(false);

				using (var sourceStream = sourceFile.GetStream(false))
				using (var destStream = destFile.GetStream(false))
				{
					await sourceStream.CopyToAsync2(destStream, this.ChunkSize, cancellationToken).ConfigureAwait(false);
				}

				if (sourceBasicInfo != null)
				{
					await destFile.SetBasicInfoAsync(
						sourceBasicInfo.CreationTime,
						sourceBasicInfo.LastAccessTime,
						sourceBasicInfo.LastWriteTime,
						sourceBasicInfo.ChangeTime,
						sourceBasicInfo.Attributes,
						cancellationToken).ConfigureAwait(false);
				}
			}
			finally
			{
				if (destFile != null)
					await destFile.CloseAsync(cancellationToken).ConfigureAwait(false);
				if (sourceFile != null)
					await sourceFile.CloseAsync(cancellationToken).ConfigureAwait(false);
			}
		}

		private async Task CopySmbToLocalAsync(
			Smb2Client smbClient,
			UncPath sourcePath,
			DateTime? sourceTimeWarpToken,
			string destinationPath,
			CancellationToken cancellationToken)
		{
			if (string.IsNullOrEmpty(sourcePath.ShareRelativePath))
				throw new ArgumentException($"Source path must include a file name: {sourcePath}", nameof(Source));

			Smb2OpenFile? sourceFile = null;
			try
			{
				sourceFile = await OpenFileReadAsync(smbClient, sourcePath, sourceTimeWarpToken, cancellationToken).ConfigureAwait(false);
				if (sourceFile.IsDirectory)
					throw new IOException($"Source path '{sourcePath}' is a directory. Copy-TBOSmbItem supports files only.");

				destinationPath = ResolveLocalDestinationPath(sourcePath, destinationPath);
				if (File.Exists(destinationPath) && !this.Force.IsPresent)
					throw new IOException($"The file '{destinationPath}' already exists.");

				if (!ShouldProcessCopy(sourcePath.ToString(), destinationPath))
					return;

				if (this.CreateDirectories.IsPresent)
					EnsureLocalDirectory(destinationPath);

				var fileMode = this.Force.IsPresent ? FileMode.Create : FileMode.CreateNew;
				using (var sourceStream = sourceFile.GetStream(false))
				using (var destStream = new FileStream(destinationPath, fileMode, FileAccess.Write, FileShare.Read, this.ChunkSize, FileOptions.SequentialScan))
				{
					await sourceStream.CopyToAsync2(destStream, this.ChunkSize, cancellationToken).ConfigureAwait(false);
				}

				if (this.PreserveTimestamps.IsPresent)
				{
					var sourceBasicInfo = await sourceFile.GetBasicInfoAsync(cancellationToken).ConfigureAwait(false);
					ApplyLocalBasicInfo(destinationPath, sourceBasicInfo);
				}

				if (this.PreserveSecurityDescriptor.IsPresent)
				{
					throw new NotSupportedException("PreserveSecurityDescriptor is only supported for SMB-to-SMB copies.");
				}
			}
			finally
			{
				if (sourceFile != null)
					await sourceFile.CloseAsync(cancellationToken).ConfigureAwait(false);
			}
		}

		private async Task CopyLocalToSmbAsync(
			Smb2Client smbClient,
			string sourcePath,
			UncPath destinationPath,
			CancellationToken cancellationToken)
		{
			var sourceInfo = new FileInfo(sourcePath);
			if (!sourceInfo.Exists)
				throw new FileNotFoundException($"Source path '{sourcePath}' does not exist.", sourcePath);
			if (0 != (sourceInfo.Attributes & FileAttributes.Directory))
				throw new IOException($"Source path '{sourcePath}' is a directory. Copy-TBOSmbItem supports files only.");

			Smb2OpenFile? destFile = null;
			try
			{
				var sourceFileName = Path.GetFileName(sourcePath);
				if (string.IsNullOrEmpty(sourceFileName))
					throw new IOException($"Source path '{sourcePath}' does not specify a file name.");

				var resolvedDest = await ResolveDestinationAsync(smbClient, destinationPath, sourceFileName, cancellationToken).ConfigureAwait(false);
				destinationPath = resolvedDest.Path;

				if (resolvedDest.Exists && !this.Force.IsPresent)
					throw new IOException($"The file '{destinationPath}' already exists.");

				if (!ShouldProcessCopy(sourcePath, destinationPath.ToString()))
					return;

				if (this.CreateDirectories.IsPresent)
					await EnsureRemoteDirectoryAsync(smbClient, destinationPath.GetDirectoryPath(), cancellationToken).ConfigureAwait(false);

				var createInfo = new Smb2CreateInfo
				{
					CreateDisposition = GetCreateDisposition(resolvedDest.Exists, this.PreserveSecurityDescriptor.IsPresent),
					DesiredAccess = (uint)Smb2AccessRights.DefaultCreateAccess,
					ShareAccess = Smb2ShareAccess.ReadWrite,
					ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
					CreateOptions = Smb2FileCreateOptions.NonDirectory | Smb2FileCreateOptions.SynchronousIoNonalert,
					FileAttributes = Winterop.FileAttributes.Normal
				};

				destFile = (Smb2OpenFile)await smbClient.CreateFileAsync(
					destinationPath,
					createInfo,
					FileAccess.ReadWrite,
					cancellationToken).ConfigureAwait(false);

				if (sourceInfo.Length > 0)
					await destFile.SetLengthAsync(sourceInfo.Length, cancellationToken).ConfigureAwait(false);

				using (var sourceStream = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read, this.ChunkSize, FileOptions.SequentialScan))
				using (var destStream = destFile.GetStream(false))
				{
					await sourceStream.CopyToAsync2(destStream, this.ChunkSize, cancellationToken).ConfigureAwait(false);
				}

				if (this.PreserveTimestamps.IsPresent)
				{
					var sourceBasicInfo = GetLocalBasicInfo(sourceInfo);
					await destFile.SetBasicInfoAsync(
						sourceBasicInfo.CreationTime,
						sourceBasicInfo.LastAccessTime,
						sourceBasicInfo.LastWriteTime,
						sourceBasicInfo.ChangeTime,
						sourceBasicInfo.Attributes,
						cancellationToken).ConfigureAwait(false);
				}
			}
			finally
			{
				if (destFile != null)
					await destFile.CloseAsync(cancellationToken).ConfigureAwait(false);
			}
		}

		private static Smb2CreateDisposition GetCreateDisposition(bool destExists, bool preserveSecurityDescriptor)
		{
			if (!destExists)
				return Smb2CreateDisposition.Create;

			return preserveSecurityDescriptor
				? Smb2CreateDisposition.Supersede
				: Smb2CreateDisposition.OverwriteIf;
		}

		private static Smb2CreateInfo CreateAttributeQuery()
		{
			return new Smb2CreateInfo
			{
				OplockLevel = Smb2OplockLevel.None,
				ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
				DesiredAccess = (uint)Smb2AccessRights.ReadAttributes,
				FileAttributes = 0,
				ShareAccess = Smb2ShareAccess.ReadWriteDelete,
				CreateDisposition = Smb2CreateDisposition.Open,
				CreateOptions = Smb2FileCreateOptions.OpenReparsePoint | Smb2FileCreateOptions.SynchronousIoNonalert,
				RequestMaximalAccess = true,
				QueryOnDiskId = true
			};
		}

		private static async Task<(UncPath Path, bool Exists)> ResolveDestinationAsync(
			Smb2Client client,
			UncPath sourcePath,
			UncPath destinationPath,
			CancellationToken cancellationToken)
		{
			string fileName = Path.GetFileName(sourcePath.ShareRelativePath ?? string.Empty);
			if (string.IsNullOrEmpty(fileName))
				throw new IOException($"Source path '{sourcePath}' does not specify a file name.");

			return await ResolveDestinationAsync(client, destinationPath, fileName, cancellationToken).ConfigureAwait(false);
		}

		private static async Task<(UncPath Path, bool Exists)> ResolveDestinationAsync(
			Smb2Client client,
			UncPath destinationPath,
			string sourceFileName,
			CancellationToken cancellationToken)
		{
			var destInfo = await TryGetEntryInfoAsync(client, destinationPath, cancellationToken).ConfigureAwait(false);
			bool exists = destInfo.Exists;
			bool isDir = destInfo.IsDir;

			if (isDir)
			{
				if (string.IsNullOrEmpty(sourceFileName))
					throw new IOException("Source path does not specify a file name.");

				destinationPath = destinationPath.Append(sourceFileName);
				exists = false;

				var fileInfo = await TryGetEntryInfoAsync(client, destinationPath, cancellationToken).ConfigureAwait(false);
				if (fileInfo.Exists && fileInfo.IsDir)
					throw new IOException($"Destination path '{destinationPath}' is a directory.");

				exists = fileInfo.Exists;
			}

			return (destinationPath, exists);
		}

		private static async Task<(bool Exists, bool IsDir)> TryGetEntryInfoAsync(
			Smb2Client client,
			UncPath path,
			CancellationToken cancellationToken)
		{
			Smb2OpenFileObjectBase? file = null;
			try
			{
				var openInfo = CreateAttributeQuery();
				file = await client.CreateFileAsync(path, openInfo, FileAccess.Read, cancellationToken).ConfigureAwait(false);
				return (true, file.IsDirectory);
			}
			catch (OperationCanceledException)
			{
				throw;
			}
			catch
			{
				return (false, false);
			}
			finally
			{
				if (file != null)
					await file.CloseAsync(cancellationToken).ConfigureAwait(false);
			}
		}

		private ResolvedPath ResolvePath(string path, string paramName)
		{
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("Path must be provided.", paramName);

			if (UncPath.TryParse(path, out var uncPath) && uncPath != null)
			{
				var snapshotPath = ResolveSnapshotPath(uncPath);
				return ResolvedPath.ForSmb(snapshotPath.ResolvedPath, snapshotPath.TimeWarpToken);
			}

			ProviderInfo? providerInfo;
			PSDriveInfo? driveInfo;
			string providerPath;
			try
			{
				providerPath = this.SessionState.Path.GetUnresolvedProviderPathFromPSPath(path, out providerInfo, out driveInfo);
			}
			catch (Exception ex)
			{
				throw new ArgumentException($"Path could not be resolved: {path}", paramName, ex);
			}

			if (providerInfo == null)
				throw new ArgumentException($"Path could not be resolved to a provider: {path}", paramName);

			if (providerInfo.Name.Equals(SmbProvider.ProviderName, StringComparison.OrdinalIgnoreCase))
			{
				if (UncPath.TryParse(providerPath, out var resolvedUnc) && resolvedUnc != null)
				{
					var snapshotPath = ResolveSnapshotPath(resolvedUnc);
					return ResolvedPath.ForSmb(snapshotPath.ResolvedPath, snapshotPath.TimeWarpToken);
				}

				throw new ArgumentException($"Resolved provider path is not a UNC path: {providerPath}", paramName);
			}

			if (providerInfo.Name.Equals("FileSystem", StringComparison.OrdinalIgnoreCase))
				return ResolvedPath.ForLocal(providerPath);

			throw new ArgumentException($"Path must be a UNC path, a {SmbProvider.ProviderName} PSDrive path, or a local file system path: {path}", paramName);
		}

		private static string ResolveLocalDestinationPath(UncPath sourcePath, string destinationPath)
		{
			if (Directory.Exists(destinationPath))
			{
				var fileName = Path.GetFileName(sourcePath.ShareRelativePath ?? string.Empty);
				if (string.IsNullOrEmpty(fileName))
					throw new IOException($"Source path '{sourcePath}' does not specify a file name.");

				destinationPath = Path.Combine(destinationPath, fileName);
			}

			if (Directory.Exists(destinationPath))
				throw new IOException($"Destination path '{destinationPath}' is a directory.");

			return destinationPath;
		}

		private static void ApplyLocalBasicInfo(string destinationPath, Smb2FileBasicInfo basicInfo)
		{
			if (basicInfo == null)
				throw new ArgumentNullException(nameof(basicInfo));

			File.SetCreationTimeUtc(destinationPath, basicInfo.CreationTime);
			File.SetLastAccessTimeUtc(destinationPath, basicInfo.LastAccessTime);
			File.SetLastWriteTimeUtc(destinationPath, basicInfo.LastWriteTime);
			File.SetAttributes(destinationPath, (FileAttributes)basicInfo.Attributes);
		}

		private static void EnsureLocalDirectory(string destinationPath)
		{
			var dir = Path.GetDirectoryName(destinationPath);
			if (string.IsNullOrWhiteSpace(dir))
				return;

			Directory.CreateDirectory(dir);
		}

		private static async Task EnsureRemoteDirectoryAsync(
			Smb2Client smbClient,
			UncPath directoryPath,
			CancellationToken cancellationToken)
		{
			if (string.IsNullOrEmpty(directoryPath.ShareRelativePath))
				return;

			string relativePath = directoryPath.ShareRelativePath;
			if (string.IsNullOrWhiteSpace(relativePath))
				return;

			var parts = relativePath.Split('\\', StringSplitOptions.RemoveEmptyEntries);
			if (parts.Length == 0)
				return;

			UncPath current = directoryPath.ShareUncPath;
			foreach (var part in parts)
			{
				current = current.Append(part);
				var info = await TryGetEntryInfoAsync(smbClient, current, cancellationToken).ConfigureAwait(false);
				if (info.Exists)
				{
					if (!info.IsDir)
						throw new IOException($"Destination path '{current}' is not a directory.");
					continue;
				}

				Smb2Directory? dir = null;
				try
				{
					dir = await smbClient.CreateDirectoryAsync(current, cancellationToken).ConfigureAwait(false);
				}
				finally
				{
					if (dir != null)
						await dir.CloseAsync(cancellationToken).ConfigureAwait(false);
				}
			}
		}

		private static Smb2FileBasicInfoSnapshot GetLocalBasicInfo(FileInfo sourceInfo)
		{
			return new Smb2FileBasicInfoSnapshot(
				sourceInfo.CreationTimeUtc,
				sourceInfo.LastAccessTimeUtc,
				sourceInfo.LastWriteTimeUtc,
				sourceInfo.LastWriteTimeUtc,
				(Winterop.FileAttributes)sourceInfo.Attributes);
		}

		private readonly struct ResolvedPath
		{
			private ResolvedPath(PathKind kind, UncPath? smbPath, string? localPath, DateTime? timeWarpToken)
			{
				this.Kind = kind;
				this.SmbPath = smbPath;
				this.LocalPath = localPath;
				this.TimeWarpToken = timeWarpToken;
			}

			public PathKind Kind { get; }
			public UncPath? SmbPath { get; }
			public string? LocalPath { get; }
			public DateTime? TimeWarpToken { get; }
			public bool HasTimeWarpToken => this.TimeWarpToken.HasValue;

			public static ResolvedPath ForSmb(UncPath path, DateTime? timeWarpToken) => new ResolvedPath(PathKind.Smb, path, null, timeWarpToken);
			public static ResolvedPath ForLocal(string path) => new ResolvedPath(PathKind.Local, null, path, null);
		}

		private enum PathKind
		{
			Smb,
			Local
		}

		private bool ShouldProcessCopy(string sourceDisplay, string destinationDisplay)
		{
			return this.ShouldProcess(destinationDisplay, $"Copy from {sourceDisplay}");
		}

		private readonly struct SnapshotPath
		{
			public SnapshotPath(UncPath resolvedPath, DateTime? timeWarpToken)
			{
				this.ResolvedPath = resolvedPath;
				this.TimeWarpToken = timeWarpToken;
			}

			public UncPath ResolvedPath { get; }
			public DateTime? TimeWarpToken { get; }
		}

		private static SnapshotPath ResolveSnapshotPath(UncPath uncPath)
		{
			if (TrySplitTimeWarpToken(uncPath, out var resolvedPath, out var timeWarpToken))
				return new SnapshotPath(resolvedPath, timeWarpToken);

			return new SnapshotPath(uncPath, null);
		}

		private static bool TrySplitTimeWarpToken(UncPath uncPath, out UncPath resolvedPath, out DateTime? timeWarpToken)
		{
			resolvedPath = uncPath;
			timeWarpToken = null;

			var relativePath = uncPath.ShareRelativePath;
			if (string.IsNullOrEmpty(relativePath))
				return false;

			var separatorIndex = relativePath.IndexOf('\\');
			var firstSegment = separatorIndex >= 0 ? relativePath.Substring(0, separatorIndex) : relativePath;
			if (!firstSegment.StartsWith("@GMT-", StringComparison.OrdinalIgnoreCase))
				return false;

			try
			{
				var snapshot = FileSnapshotInfo.Parse(firstSegment.ToUpperInvariant());
				timeWarpToken = snapshot.Timestamp;
			}
			catch
			{
				return false;
			}

			var remainder = separatorIndex >= 0 ? relativePath.Substring(separatorIndex + 1) : null;
			resolvedPath = string.IsNullOrEmpty(remainder)
				? new UncPath(uncPath.ServerName, uncPath.Port, uncPath.ShareName, string.Empty)
				: new UncPath(uncPath.ServerName, uncPath.Port, uncPath.ShareName, remainder);
			return true;
		}

		private static async Task<Smb2OpenFile> OpenFileReadAsync(
			Smb2Client smbClient,
			UncPath path,
			DateTime? timeWarpToken,
			CancellationToken cancellationToken)
		{
			if (!timeWarpToken.HasValue)
				return await smbClient.OpenFileReadAsync(path, cancellationToken).ConfigureAwait(false);

			var createInfo = new Smb2CreateInfo
			{
				CreateDisposition = Smb2CreateDisposition.Open,
				DesiredAccess = (uint)Smb2AccessRights.DefaultOpenReadAccess,
				ShareAccess = Smb2ShareAccess.Read,
				ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
				CreateOptions = Smb2FileCreateOptions.NonDirectory
					| Smb2FileCreateOptions.SynchronousIoNonalert
					| Smb2FileCreateOptions.OpenForBackupIntent,
				FileAttributes = Winterop.FileAttributes.Normal,
				TimeWarpToken = timeWarpToken
			};

			return (Smb2OpenFile)await smbClient.CreateFileAsync(path, createInfo, FileAccess.Read, cancellationToken).ConfigureAwait(false);
		}

		private readonly struct Smb2FileBasicInfoSnapshot
		{
			public Smb2FileBasicInfoSnapshot(
				DateTime creationTime,
				DateTime lastAccessTime,
				DateTime lastWriteTime,
				DateTime changeTime,
				Winterop.FileAttributes attributes)
			{
				this.CreationTime = creationTime;
				this.LastAccessTime = lastAccessTime;
				this.LastWriteTime = lastWriteTime;
				this.ChangeTime = changeTime;
				this.Attributes = attributes;
			}

			public DateTime CreationTime { get; }
			public DateTime LastAccessTime { get; }
			public DateTime LastWriteTime { get; }
			public DateTime ChangeTime { get; }
			public Winterop.FileAttributes Attributes { get; }
		}
	}
}
