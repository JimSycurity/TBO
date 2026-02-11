using System;
using System.Collections.Generic;
using System.IO;
using System.Management.Automation;
using System.Text.Json;
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
		public SwitchParameter FollowReparse { get; set; }

		[Parameter]
		public int ChunkSize { get; set; } = Smb2Client.DefaultChunkSize;

		[Parameter]
		public SwitchParameter Cache { get; set; }

		[Parameter]
		public string? CachePath { get; set; }

		private CancellationTokenSource? _cancelSource;
		private ISmbProviderInfo? _smb;

		protected override void ProcessRecord(ISmbProviderInfo smb)
		{
			this._cancelSource ??= new CancellationTokenSource();
			this._smb = smb;
			CopyAsync(smb, this._cancelSource.Token).ConfigureAwait(false).GetAwaiter().GetResult();
		}

		protected override void StopProcessing()
		{
			this._cancelSource?.Cancel();
			base.StopProcessing();
		}

	private async Task CopyAsync(ISmbProviderInfo smb, CancellationToken cancellationToken)
	{
		var source = ResolvePath(this.Source, nameof(Source));
		var destination = ResolvePath(this.Destination, nameof(Destination));

		if (source.Kind == PathKind.Local && destination.Kind == PathKind.Local)
			throw new ArgumentException("At least one path must be a UNC path or a TBO.Smb2 PSDrive path.");
		if (destination.Kind == PathKind.Smb && destination.HasTimeWarpToken)
			throw new NotSupportedException("Snapshot paths are read-only.");
		if (this.PreserveSecurityDescriptor.IsPresent && (source.Kind == PathKind.Local || destination.Kind == PathKind.Local))
			throw new NotSupportedException("PreserveSecurityDescriptor is only supported for SMB-to-SMB copies.");

		var sourceFileSystem = TryGetCustomSourceFileSystem(smb, source, destination);
		Smb2Client? smbClient = null;
		bool sourceIsDirectory = false;

		if (source.Kind == PathKind.Smb)
		{
			if (sourceFileSystem != null)
			{
				var info = TryGetSmbSourceInfoViaFileSystem(sourceFileSystem, source.SmbPath!, cancellationToken);
				if (!info.Exists)
					throw new FileNotFoundException($"Source path '{source.SmbPath}' does not exist.");
				sourceIsDirectory = info.IsDirectory;
			}
			else
			{
				smbClient = smb.SmbClient;
				var info = await TryGetEntryInfoAsync(smbClient, source.SmbPath!, source.TimeWarpToken, cancellationToken).ConfigureAwait(false);
				if (!info.Exists)
					throw new FileNotFoundException($"Source path '{source.SmbPath}' does not exist.");
				sourceIsDirectory = info.IsDir;
			}
		}
		else
		{
			if (Directory.Exists(source.LocalPath!))
			{
				sourceIsDirectory = true;
			}
			else if (!File.Exists(source.LocalPath!))
			{
				throw new FileNotFoundException($"Source path '{source.LocalPath}' does not exist.", source.LocalPath);
			}
		}

		if (sourceIsDirectory)
		{
			if (source.Kind == PathKind.Smb && destination.Kind == PathKind.Smb)
			{
				var smbClientForCopy = smbClient ?? smb.SmbClient;
				await CopySmbDirectoryToSmbAsync(smbClientForCopy, source.SmbPath!, source.TimeWarpToken, destination.SmbPath!, cancellationToken).ConfigureAwait(false);
				return;
			}

			if (source.Kind == PathKind.Smb)
			{
				if (sourceFileSystem != null)
				{
					await CopySmbDirectoryToLocalViaFileSystemAsync(sourceFileSystem, source.SmbPath!, destination.LocalPath!, cancellationToken).ConfigureAwait(false);
				}
				else
				{
					var smbClientForCopy = smbClient ?? smb.SmbClient;
					await CopySmbDirectoryToLocalAsync(smbClientForCopy, source.SmbPath!, source.TimeWarpToken, destination.LocalPath!, cancellationToken).ConfigureAwait(false);
				}
				return;
			}

			var smbClientForLocalSource = smbClient ?? smb.SmbClient;
			await CopyLocalDirectoryToSmbAsync(smbClientForLocalSource, source.LocalPath!, destination.SmbPath!, cancellationToken).ConfigureAwait(false);
			return;
		}

		if (destination.HasTimeWarpToken)
			throw new NotSupportedException("Snapshot paths are read-only.");

		if (source.Kind == PathKind.Smb && destination.Kind == PathKind.Smb)
		{
			var smbClientForCopy = smbClient ?? smb.SmbClient;
			await CopySmbToSmbAsync(smbClientForCopy, source.SmbPath!, source.TimeWarpToken, destination.SmbPath!, cancellationToken).ConfigureAwait(false);
			return;
		}

		if (source.Kind == PathKind.Smb)
		{
			if (sourceFileSystem != null && !source.TimeWarpToken.HasValue)
			{
				await CopySmbToLocalViaFileSystemAsync(sourceFileSystem, source.SmbPath!, destination.LocalPath!, cancellationToken).ConfigureAwait(false);
			}
			else
			{
				var smbClientForCopy = smbClient ?? smb.SmbClient;
				await CopySmbToLocalAsync(smbClientForCopy, source.SmbPath!, source.TimeWarpToken, destination.LocalPath!, cancellationToken).ConfigureAwait(false);
			}
			return;
		}

		var smbClientForLocalSourceFile = smbClient ?? smb.SmbClient;
		await CopyLocalToSmbAsync(smbClientForLocalSourceFile, source.LocalPath!, destination.SmbPath!, cancellationToken).ConfigureAwait(false);
	}

	private async Task CopySmbDirectoryToSmbAsync(
		Smb2Client smbClient,
		UncPath sourcePath,
		DateTime? sourceTimeWarpToken,
		UncPath destinationPath,
		CancellationToken cancellationToken)
	{
		var sourceDirectoryName = GetSmbDirectoryName(sourcePath);
		var destinationRoot = await ResolveSmbDirectoryDestinationAsync(
			smbClient,
			sourceDirectoryName,
			destinationPath,
			cancellationToken).ConfigureAwait(false);

		if (!ShouldProcessCopy(sourcePath.ToString(), destinationRoot.ToString()))
			return;

		var recordActivity = this.ResolveCacheIngestionEnabled(this.Cache);
		Exception? operationFailure = null;
		try
		{
			await CopySmbDirectoryToSmbCoreAsync(
				smbClient,
				sourcePath,
				sourceTimeWarpToken,
				destinationRoot,
				new HashSet<ulong>(),
				cancellationToken).ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			operationFailure = ex;
			throw;
		}
		finally
		{
			RecordCopyActivity(
				enabled: recordActivity,
				destinationServerName: destinationRoot.ServerName,
				sourceDisplay: sourcePath.ToString(),
				destinationDisplay: destinationRoot.ToString(),
				isDirectory: true,
				success: operationFailure == null,
				failureReason: operationFailure?.Message);
		}
	}

	private async Task CopySmbDirectoryToLocalAsync(
		Smb2Client smbClient,
		UncPath sourcePath,
		DateTime? sourceTimeWarpToken,
		string destinationPath,
		CancellationToken cancellationToken)
	{
		var sourceDirectoryName = GetSmbDirectoryName(sourcePath);
		var destinationRoot = ResolveLocalDirectoryDestination(sourceDirectoryName, destinationPath);

		if (!ShouldProcessCopy(sourcePath.ToString(), destinationRoot))
			return;

		await CopySmbDirectoryToLocalCoreAsync(
			smbClient,
			sourcePath,
			sourceTimeWarpToken,
			destinationRoot,
			new HashSet<ulong>(),
			cancellationToken).ConfigureAwait(false);
	}

	private async Task CopySmbDirectoryToLocalViaFileSystemAsync(
		ISmbFileSystem sourceFileSystem,
		UncPath sourcePath,
		string destinationPath,
		CancellationToken cancellationToken)
	{
		var sourceDirectoryName = GetSmbDirectoryName(sourcePath);
		var destinationRoot = ResolveLocalDirectoryDestination(sourceDirectoryName, destinationPath);

		if (!ShouldProcessCopy(sourcePath.ToString(), destinationRoot))
			return;

		await CopySmbDirectoryToLocalViaFileSystemCoreAsync(
			sourceFileSystem,
			sourcePath,
			destinationRoot,
			new HashSet<ulong>(),
			cancellationToken).ConfigureAwait(false);
	}

	private async Task CopySmbDirectoryToLocalViaFileSystemCoreAsync(
		ISmbFileSystem sourceFileSystem,
		UncPath sourcePath,
		string destinationPath,
		HashSet<ulong> followedReparseDirectoryIds,
		CancellationToken cancellationToken)
	{
		EnsureLocalDirectoryExists(destinationPath);

		using var sourceDir = sourceFileSystem.OpenDirectory(sourcePath, cancellationToken);
		var entries = sourceDir.QueryEntries(
			"*",
			Smb2Directory.Smb2DirQueryOptions.QueryReparseInfo,
			SecurityInfo.None,
			Smb2Directory.DefaultQueryBufferSize,
			cancellationToken);

		foreach (var entry in entries)
		{
			if (string.IsNullOrEmpty(entry.FileName))
				continue;
			if (entry.FileName is "." or "..")
				continue;

			bool isDirectory = (entry.FileAttributes & Winterop.FileAttributes.Directory) != 0;
			bool isReparse = (entry.FileAttributes & Winterop.FileAttributes.ReparsePoint) != 0;
			var childSourcePath = sourcePath.Append(entry.FileName);

			if (isDirectory)
			{
				if (isReparse && !ShouldFollowSmbReparseDirectory(entry, childSourcePath, followedReparseDirectoryIds, out var skipReason))
				{
					this.WriteVerboseSafe(skipReason);
					continue;
				}

				if (isReparse)
					this.WriteVerboseSafe(BuildFollowingSmbReparseDirectoryMessage(childSourcePath, entry.ReparseTag));

				await CopySmbDirectoryToLocalViaFileSystemCoreAsync(
					sourceFileSystem,
					childSourcePath,
					Path.Combine(destinationPath, entry.FileName),
					followedReparseDirectoryIds,
					cancellationToken).ConfigureAwait(false);
				continue;
			}

			await CopySmbToLocalViaFileSystemAsync(
				sourceFileSystem,
				childSourcePath,
				Path.Combine(destinationPath, entry.FileName),
				cancellationToken,
				shouldProcess: false).ConfigureAwait(false);
		}

		if (this.PreserveTimestamps.IsPresent)
		{
			this.WriteVerboseSafe(
				$"Copy-TBOSmbItem: source metadata for '{sourcePath}' is unavailable from the configured file-system provider; directory timestamps were not preserved.");
		}
	}

	private async Task CopyLocalDirectoryToSmbAsync(
		Smb2Client smbClient,
		string sourcePath,
		UncPath destinationPath,
		CancellationToken cancellationToken)
	{
		var sourceDirectoryName = GetLocalDirectoryName(sourcePath);
		var destinationRoot = await ResolveSmbDirectoryDestinationAsync(
			smbClient,
			sourceDirectoryName,
			destinationPath,
			cancellationToken).ConfigureAwait(false);

		if (!ShouldProcessCopy(sourcePath, destinationRoot.ToString()))
			return;

		var recordActivity = this.ResolveCacheIngestionEnabled(this.Cache);
		Exception? operationFailure = null;
		try
		{
			await CopyLocalDirectoryToSmbCoreAsync(
				smbClient,
				sourcePath,
				destinationRoot,
				new HashSet<string>(StringComparer.OrdinalIgnoreCase),
				cancellationToken).ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			operationFailure = ex;
			throw;
		}
		finally
		{
			RecordCopyActivity(
				enabled: recordActivity,
				destinationServerName: destinationRoot.ServerName,
				sourceDisplay: sourcePath,
				destinationDisplay: destinationRoot.ToString(),
				isDirectory: true,
				success: operationFailure == null,
				failureReason: operationFailure?.Message);
		}
	}

	private async Task CopySmbDirectoryToSmbCoreAsync(
		Smb2Client smbClient,
		UncPath sourcePath,
		DateTime? sourceTimeWarpToken,
		UncPath destinationPath,
		HashSet<ulong> followedReparseDirectoryIds,
		CancellationToken cancellationToken)
	{
		await EnsureRemoteDirectoryExistsAsync(smbClient, destinationPath, cancellationToken).ConfigureAwait(false);

		Smb2Directory? sourceDir = null;
		Smb2FileBasicInfo? sourceBasicInfo = null;
		SecurityDescriptor? sourceSecurityDescriptor = null;
		try
		{
			sourceDir = await OpenDirectoryAsync(
				smbClient,
				sourcePath,
				sourceTimeWarpToken,
				GetDirectoryReadAccess(this.PreserveSecurityDescriptor.IsPresent),
				cancellationToken).ConfigureAwait(false);

			if (this.PreserveTimestamps.IsPresent)
				sourceBasicInfo = await sourceDir.GetBasicInfoAsync(cancellationToken).ConfigureAwait(false);

			if (this.PreserveSecurityDescriptor.IsPresent)
			{
				sourceSecurityDescriptor = await sourceDir.GetSecurityAsync(
					SecurityInfo.Owner | SecurityInfo.Group | SecurityInfo.Dacl | SecurityInfo.Sacl,
					8192,
					cancellationToken).ConfigureAwait(false);
			}

			var entries = await sourceDir.QueryDirAsync(
				"*",
				Smb2Directory.Smb2DirQueryOptions.QueryReparseInfo,
				SecurityInfo.None,
				Smb2Directory.DefaultQueryBufferSize,
				cancellationToken).ConfigureAwait(false);

			foreach (var entry in entries)
			{
				if (string.IsNullOrEmpty(entry.FileName))
					continue;
				if (entry.FileName is "." or "..")
					continue;

				bool isDirectory = (entry.FileAttributes & Winterop.FileAttributes.Directory) != 0;
				bool isReparse = (entry.FileAttributes & Winterop.FileAttributes.ReparsePoint) != 0;
				var childSourcePath = sourcePath.Append(entry.FileName);

				if (isDirectory)
				{
					if (isReparse && !ShouldFollowSmbReparseDirectory(entry, childSourcePath, followedReparseDirectoryIds, out var skipReason))
					{
						this.WriteVerboseSafe(skipReason);
						continue;
					}

					if (isReparse)
						this.WriteVerboseSafe(BuildFollowingSmbReparseDirectoryMessage(childSourcePath, entry.ReparseTag));

					await CopySmbDirectoryToSmbCoreAsync(
						smbClient,
						childSourcePath,
						sourceTimeWarpToken,
						destinationPath.Append(entry.FileName),
						followedReparseDirectoryIds,
						cancellationToken).ConfigureAwait(false);
					continue;
				}

				await CopySmbToSmbAsync(
					smbClient,
					childSourcePath,
					sourceTimeWarpToken,
					destinationPath.Append(entry.FileName),
					cancellationToken,
					shouldProcess: false).ConfigureAwait(false);
			}
		}
		finally
		{
			if (sourceDir != null)
				await sourceDir.CloseAsync(cancellationToken).ConfigureAwait(false);
		}

		if (sourceBasicInfo == null && sourceSecurityDescriptor == null)
			return;

		Smb2Directory? destDir = null;
		try
		{
			destDir = await OpenDirectoryAsync(
				smbClient,
				destinationPath,
				null,
				GetDirectoryWriteAccess(this.PreserveSecurityDescriptor.IsPresent),
				cancellationToken).ConfigureAwait(false);

			if (sourceBasicInfo != null)
			{
				await destDir.SetBasicInfoAsync(
					sourceBasicInfo.CreationTime,
					sourceBasicInfo.LastAccessTime,
					sourceBasicInfo.LastWriteTime,
					sourceBasicInfo.ChangeTime,
					sourceBasicInfo.Attributes,
					cancellationToken).ConfigureAwait(false);
			}

			if (sourceSecurityDescriptor != null)
			{
				await destDir.SetSecurityAsync(
					sourceSecurityDescriptor,
					SecurityInfo.Owner | SecurityInfo.Group | SecurityInfo.Dacl | SecurityInfo.Sacl,
					cancellationToken).ConfigureAwait(false);
			}
		}
		finally
		{
			if (destDir != null)
				await destDir.CloseAsync(cancellationToken).ConfigureAwait(false);
		}
	}

	private async Task CopySmbDirectoryToLocalCoreAsync(
		Smb2Client smbClient,
		UncPath sourcePath,
		DateTime? sourceTimeWarpToken,
		string destinationPath,
		HashSet<ulong> followedReparseDirectoryIds,
		CancellationToken cancellationToken)
	{
		EnsureLocalDirectoryExists(destinationPath);

		Smb2Directory? sourceDir = null;
		Smb2FileBasicInfo? sourceBasicInfo = null;
		try
		{
			sourceDir = await OpenDirectoryAsync(
				smbClient,
				sourcePath,
				sourceTimeWarpToken,
				GetDirectoryReadAccess(false),
				cancellationToken).ConfigureAwait(false);

			if (this.PreserveTimestamps.IsPresent)
				sourceBasicInfo = await sourceDir.GetBasicInfoAsync(cancellationToken).ConfigureAwait(false);

			var entries = await sourceDir.QueryDirAsync(
				"*",
				Smb2Directory.Smb2DirQueryOptions.QueryReparseInfo,
				SecurityInfo.None,
				Smb2Directory.DefaultQueryBufferSize,
				cancellationToken).ConfigureAwait(false);

			foreach (var entry in entries)
			{
				if (string.IsNullOrEmpty(entry.FileName))
					continue;
				if (entry.FileName is "." or "..")
					continue;

				bool isDirectory = (entry.FileAttributes & Winterop.FileAttributes.Directory) != 0;
				bool isReparse = (entry.FileAttributes & Winterop.FileAttributes.ReparsePoint) != 0;
				var childSourcePath = sourcePath.Append(entry.FileName);

				if (isDirectory)
				{
					if (isReparse && !ShouldFollowSmbReparseDirectory(entry, childSourcePath, followedReparseDirectoryIds, out var skipReason))
					{
						this.WriteVerboseSafe(skipReason);
						continue;
					}

					if (isReparse)
						this.WriteVerboseSafe(BuildFollowingSmbReparseDirectoryMessage(childSourcePath, entry.ReparseTag));

					await CopySmbDirectoryToLocalCoreAsync(
						smbClient,
						childSourcePath,
						sourceTimeWarpToken,
						Path.Combine(destinationPath, entry.FileName),
						followedReparseDirectoryIds,
						cancellationToken).ConfigureAwait(false);
					continue;
				}

				await CopySmbToLocalAsync(
					smbClient,
					childSourcePath,
					sourceTimeWarpToken,
					Path.Combine(destinationPath, entry.FileName),
					cancellationToken,
					shouldProcess: false).ConfigureAwait(false);
			}
		}
		finally
		{
			if (sourceDir != null)
				await sourceDir.CloseAsync(cancellationToken).ConfigureAwait(false);
		}

		if (sourceBasicInfo != null)
			ApplyLocalBasicInfo(destinationPath, sourceBasicInfo);
	}

	private async Task CopyLocalDirectoryToSmbCoreAsync(
		Smb2Client smbClient,
		string sourcePath,
		UncPath destinationPath,
		HashSet<string> followedReparseTargets,
		CancellationToken cancellationToken)
	{
		var sourceInfo = new DirectoryInfo(sourcePath);
		if (!sourceInfo.Exists)
			throw new DirectoryNotFoundException($"Source path '{sourcePath}' does not exist.");

		if ((sourceInfo.Attributes & FileAttributes.ReparsePoint) != 0
			&& !ShouldFollowLocalReparseDirectory(sourceInfo, followedReparseTargets, out var rootSkipReason))
		{
			this.WriteVerboseSafe(rootSkipReason);
			return;
		}

		if ((sourceInfo.Attributes & FileAttributes.ReparsePoint) != 0)
			this.WriteVerboseSafe(BuildFollowingLocalReparseDirectoryMessage(sourceInfo.FullName));

		await EnsureRemoteDirectoryExistsAsync(smbClient, destinationPath, cancellationToken).ConfigureAwait(false);

		foreach (var dir in sourceInfo.EnumerateDirectories())
		{
			cancellationToken.ThrowIfCancellationRequested();
			if ((dir.Attributes & FileAttributes.ReparsePoint) != 0
				&& !ShouldFollowLocalReparseDirectory(dir, followedReparseTargets, out var skipReason))
			{
				this.WriteVerboseSafe(skipReason);
				continue;
			}

			if ((dir.Attributes & FileAttributes.ReparsePoint) != 0)
				this.WriteVerboseSafe(BuildFollowingLocalReparseDirectoryMessage(dir.FullName));

			await CopyLocalDirectoryToSmbCoreAsync(
				smbClient,
				dir.FullName,
				destinationPath.Append(dir.Name),
				followedReparseTargets,
				cancellationToken).ConfigureAwait(false);
		}

		foreach (var file in sourceInfo.EnumerateFiles())
		{
			cancellationToken.ThrowIfCancellationRequested();
			await CopyLocalToSmbAsync(
				smbClient,
				file.FullName,
				destinationPath.Append(file.Name),
				cancellationToken,
				shouldProcess: false).ConfigureAwait(false);
		}

		if (this.PreserveTimestamps.IsPresent)
		{
			var sourceBasicInfo = GetLocalBasicInfo(sourceInfo);
			Smb2Directory? destDir = null;
			try
			{
				destDir = await OpenDirectoryAsync(
					smbClient,
					destinationPath,
					null,
					GetDirectoryWriteAccess(false),
					cancellationToken).ConfigureAwait(false);

				await destDir.SetBasicInfoAsync(
					sourceBasicInfo.CreationTime,
					sourceBasicInfo.LastAccessTime,
					sourceBasicInfo.LastWriteTime,
					sourceBasicInfo.ChangeTime,
					sourceBasicInfo.Attributes,
					cancellationToken).ConfigureAwait(false);
			}
			finally
			{
				if (destDir != null)
					await destDir.CloseAsync(cancellationToken).ConfigureAwait(false);
			}
		}
	}

	private async Task CopySmbToSmbAsync(
		Smb2Client smbClient,
		UncPath sourcePath,
		DateTime? sourceTimeWarpToken,
		UncPath destinationPath,
		CancellationToken cancellationToken,
		bool shouldProcess = true)
	{
			if (string.IsNullOrEmpty(sourcePath.ShareRelativePath))
				throw new ArgumentException($"Source path must include a file name: {sourcePath}", nameof(Source));

			var recordActivity = shouldProcess && this.ResolveCacheIngestionEnabled(this.Cache);
			var approved = false;
			Exception? operationFailure = null;

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

				if (shouldProcess && !ShouldProcessCopy(sourcePath.ToString(), destinationPath.ToString()))
					return;

				approved = recordActivity;

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
			catch (Exception ex)
			{
				operationFailure = ex;
				throw;
			}
			finally
			{
				if (destFile != null)
					await destFile.CloseAsync(cancellationToken).ConfigureAwait(false);
				if (sourceFile != null)
					await sourceFile.CloseAsync(cancellationToken).ConfigureAwait(false);

				if (approved)
				{
					RecordCopyActivity(
						enabled: recordActivity,
						destinationServerName: destinationPath.ServerName,
						sourceDisplay: sourcePath.ToString(),
						destinationDisplay: destinationPath.ToString(),
						isDirectory: false,
						success: operationFailure == null,
						failureReason: operationFailure?.Message);
				}
			}
		}

		private async Task CopySmbToLocalViaFileSystemAsync(
			ISmbFileSystem sourceFileSystem,
			UncPath sourcePath,
			string destinationPath,
			CancellationToken cancellationToken,
			bool shouldProcess = true)
		{
			var sourceInfo = TryGetSmbSourceInfoViaFileSystem(sourceFileSystem, sourcePath, cancellationToken);
			if (!sourceInfo.Exists)
				throw new FileNotFoundException($"Source path '{sourcePath}' does not exist.");
			if (sourceInfo.IsDirectory)
				throw new IOException($"Source path '{sourcePath}' is a directory. Copy-TBOSmbItem supports files only.");

			destinationPath = ResolveLocalDestinationPath(sourcePath, destinationPath);

			if (File.Exists(destinationPath) && !this.Force.IsPresent)
				throw new IOException($"The file '{destinationPath}' already exists.");
			if (Directory.Exists(destinationPath))
				throw new IOException($"Destination path '{destinationPath}' is a directory.");

			if (shouldProcess && !ShouldProcessCopy(sourcePath.ToString(), destinationPath))
				return;

			if (this.CreateDirectories.IsPresent)
				EnsureLocalDirectory(destinationPath);
			else
			{
				var destinationDirectory = Path.GetDirectoryName(destinationPath);
				if (!string.IsNullOrWhiteSpace(destinationDirectory) && !Directory.Exists(destinationDirectory))
					throw new IOException($"Destination directory '{destinationDirectory}' does not exist. Use -CreateDirectories to create it.");
			}

			using var sourceFile = sourceFileSystem.OpenFileRead(sourcePath, cancellationToken);
			await using (var sourceStream = sourceFile.OpenRead())
			await using (var destStream = new FileStream(destinationPath, FileMode.Create, FileAccess.Write, FileShare.None, this.ChunkSize, useAsync: true))
			{
				await sourceStream.CopyToAsync2(destStream, this.ChunkSize, cancellationToken).ConfigureAwait(false);
			}

			if (this.PreserveTimestamps.IsPresent)
			{
				this.WriteVerboseSafe(
					$"Copy-TBOSmbItem: source metadata for '{sourcePath}' is unavailable from the configured file-system provider; file timestamps were not preserved.");
			}
		}

		private async Task CopySmbToLocalAsync(
			Smb2Client smbClient,
			UncPath sourcePath,
			DateTime? sourceTimeWarpToken,
			string destinationPath,
			CancellationToken cancellationToken,
			bool shouldProcess = true)
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

				if (shouldProcess && !ShouldProcessCopy(sourcePath.ToString(), destinationPath))
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
			CancellationToken cancellationToken,
			bool shouldProcess = true)
		{
			var sourceInfo = new FileInfo(sourcePath);
			if (!sourceInfo.Exists)
				throw new FileNotFoundException($"Source path '{sourcePath}' does not exist.", sourcePath);
			if (0 != (sourceInfo.Attributes & FileAttributes.Directory))
				throw new IOException($"Source path '{sourcePath}' is a directory. Copy-TBOSmbItem supports files only.");

			var recordActivity = shouldProcess && this.ResolveCacheIngestionEnabled(this.Cache);
			var approved = false;
			Exception? operationFailure = null;

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

				if (shouldProcess && !ShouldProcessCopy(sourcePath, destinationPath.ToString()))
					return;

				approved = recordActivity;

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
			catch (Exception ex)
			{
				operationFailure = ex;
				throw;
			}
			finally
			{
				if (destFile != null)
					await destFile.CloseAsync(cancellationToken).ConfigureAwait(false);

				if (approved)
				{
					RecordCopyActivity(
						enabled: recordActivity,
						destinationServerName: destinationPath.ServerName,
						sourceDisplay: sourcePath,
						destinationDisplay: destinationPath.ToString(),
						isDirectory: false,
						success: operationFailure == null,
						failureReason: operationFailure?.Message);
				}
			}
		}

		private void RecordCopyActivity(
			bool enabled,
			string destinationServerName,
			string sourceDisplay,
			string destinationDisplay,
			bool isDirectory,
			bool success,
			string? failureReason)
		{
			if (!enabled)
				return;

			var smb = this._smb;
			if (smb == null)
				return;

			string? contextJson = null;
			contextJson = JsonSerializer.Serialize(new
			{
				source = sourceDisplay,
				destination = destinationDisplay,
				isDirectory,
				force = this.Force.IsPresent,
				createDirectories = this.CreateDirectories.IsPresent,
				preserveTimestamps = this.PreserveTimestamps.IsPresent,
				preserveSecurityDescriptor = this.PreserveSecurityDescriptor.IsPresent,
				chunkSize = this.ChunkSize
			});

			TboCacheWriteActivities.TryRecord(
				cmdlet: this,
				smb: smb,
				enabled: enabled,
				cachePath: this.CachePath,
				serverName: destinationServerName,
				kind: TboCacheWriteActivities.KindFileSystem,
				action: TboCacheWriteActivities.ActionCopyItem,
				target: destinationDisplay,
				path: destinationDisplay,
				valueName: null,
				valueType: null,
				beforeBlobKind: null,
				beforeBlob: null,
				afterBlobKind: null,
				afterBlob: null,
				contextJson: contextJson,
				success: success,
				failureReason: failureReason);
		}

		private static Smb2CreateDisposition GetCreateDisposition(bool destExists, bool preserveSecurityDescriptor)
		{
			if (!destExists)
				return Smb2CreateDisposition.Create;

			return preserveSecurityDescriptor
				? Smb2CreateDisposition.Supersede
				: Smb2CreateDisposition.OverwriteIf;
		}

		private static uint GetDirectoryReadAccess(bool includeSecurity)
		{
			uint access = (uint)Smb2AccessRights.DefaultOpenDirAccess;
			if (includeSecurity)
				access |= (uint)(Smb2AccessRights.ReadControl | Smb2AccessRights.AccessSystemSecurity);
			return access;
		}

		private static uint GetDirectoryWriteAccess(bool includeSecurity)
		{
			uint access = (uint)(Smb2AccessRights.DefaultOpenDirAccess | Smb2AccessRights.WriteAttributes);
			if (includeSecurity)
			{
				access |= (uint)(Smb2AccessRights.ReadControl
					| Smb2AccessRights.WriteDac
					| Smb2AccessRights.WriteOwner
					| Smb2AccessRights.AccessSystemSecurity);
			}
			return access;
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

		private static string GetSmbDirectoryName(UncPath sourcePath)
		{
			var relativePath = sourcePath.ShareRelativePath?.TrimEnd('\\', '/');
			var name = Path.GetFileName(relativePath ?? string.Empty);
			if (string.IsNullOrWhiteSpace(name))
				throw new IOException($"Source path '{sourcePath}' does not specify a directory name.");
			return name;
		}

		private static string GetLocalDirectoryName(string sourcePath)
		{
			var trimmed = sourcePath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
			var name = Path.GetFileName(trimmed);
			if (string.IsNullOrWhiteSpace(name))
				throw new IOException($"Source path '{sourcePath}' does not specify a directory name.");
			return name;
		}

		private async Task<UncPath> ResolveSmbDirectoryDestinationAsync(
			Smb2Client smbClient,
			string sourceDirectoryName,
			UncPath destinationPath,
			CancellationToken cancellationToken)
		{
			if (string.IsNullOrWhiteSpace(sourceDirectoryName))
				throw new IOException("Source path does not specify a directory name.");

			var destInfo = await TryGetEntryInfoAsync(smbClient, destinationPath, cancellationToken).ConfigureAwait(false);
			if (destInfo.Exists && !destInfo.IsDir)
				throw new IOException($"Destination path '{destinationPath}' is not a directory.");

			if (destInfo.Exists)
				return destinationPath.Append(sourceDirectoryName);

			return destinationPath;
		}

		private static string ResolveLocalDirectoryDestination(string sourceDirectoryName, string destinationPath)
		{
			if (Directory.Exists(destinationPath))
				return Path.Combine(destinationPath, sourceDirectoryName);
			if (File.Exists(destinationPath))
				throw new IOException($"Destination path '{destinationPath}' is not a directory.");
			return destinationPath;
		}

		private async Task EnsureRemoteDirectoryExistsAsync(
			Smb2Client smbClient,
			UncPath directoryPath,
			CancellationToken cancellationToken)
		{
			var info = await TryGetEntryInfoAsync(smbClient, directoryPath, cancellationToken).ConfigureAwait(false);
			if (info.Exists)
			{
				if (!info.IsDir)
					throw new IOException($"Destination path '{directoryPath}' is not a directory.");
				return;
			}

			if (!this.CreateDirectories.IsPresent)
				throw new IOException($"Destination directory '{directoryPath}' does not exist. Use -CreateDirectories to create it.");

			await EnsureRemoteDirectoryAsync(smbClient, directoryPath, cancellationToken).ConfigureAwait(false);
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
			return await TryGetEntryInfoAsync(client, path, null, cancellationToken).ConfigureAwait(false);
		}

		private static async Task<(bool Exists, bool IsDir)> TryGetEntryInfoAsync(
			Smb2Client client,
			UncPath path,
			DateTime? timeWarpToken,
			CancellationToken cancellationToken)
		{
			Smb2OpenFileObjectBase? file = null;
			try
			{
				var openInfo = CreateAttributeQuery();
				if (timeWarpToken.HasValue)
					openInfo.TimeWarpToken = timeWarpToken;
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

		private static ISmbFileSystem? TryGetCustomSourceFileSystem(
			ISmbProviderInfo smb,
			ResolvedPath source,
			ResolvedPath destination)
		{
			if (source.Kind != PathKind.Smb || destination.Kind != PathKind.Local || source.HasTimeWarpToken)
				return null;

			if (smb is ISmbFileSystemProvider provider)
				return provider.FileSystem;

			return null;
		}

		private static (bool Exists, bool IsDirectory) TryGetSmbSourceInfoViaFileSystem(
			ISmbFileSystem sourceFileSystem,
			UncPath sourcePath,
			CancellationToken cancellationToken)
		{
			ISmbDirectory? sourceDirectory = null;
			try
			{
				sourceDirectory = sourceFileSystem.OpenDirectory(sourcePath, cancellationToken);
				return (true, true);
			}
			catch
			{
			}
			finally
			{
				sourceDirectory?.Dispose();
			}

			ISmbFile? sourceFile = null;
			try
			{
				sourceFile = sourceFileSystem.OpenFileRead(sourcePath, cancellationToken);
				return (true, false);
			}
			catch
			{
				return (false, false);
			}
			finally
			{
				sourceFile?.Dispose();
			}
		}

		private bool ShouldFollowSmbReparseDirectory(
			Smb2DirEntry entry,
			UncPath reparsePath,
			HashSet<ulong> followedReparseDirectoryIds,
			out string skipReason)
		{
			if (!this.FollowReparse.IsPresent)
			{
				skipReason = BuildSkippedSmbReparseDirectoryMessage(reparsePath, entry.ReparseTag);
				return false;
			}

			if (entry.FileId != 0 && !followedReparseDirectoryIds.Add(entry.FileId))
			{
				skipReason =
					$"Copy-TBOSmbItem skipped reparse directory '{reparsePath}' to avoid a traversal cycle (revisited file ID 0x{entry.FileId:X16}).";
				return false;
			}

			skipReason = string.Empty;
			return true;
		}

		private bool ShouldFollowLocalReparseDirectory(
			DirectoryInfo directory,
			HashSet<string> followedReparseTargets,
			out string skipReason)
		{
			if (!this.FollowReparse.IsPresent)
			{
				skipReason = BuildSkippedLocalReparseDirectoryMessage(directory.FullName);
				return false;
			}

			var trackingKey = GetLocalReparseTrackingKey(directory);
			if (!followedReparseTargets.Add(trackingKey))
			{
				skipReason =
					$"Copy-TBOSmbItem skipped reparse directory '{directory.FullName}' to avoid a traversal cycle (resolved target '{trackingKey}' was already visited).";
				return false;
			}

			skipReason = string.Empty;
			return true;
		}

		private static string GetLocalReparseTrackingKey(DirectoryInfo directory)
		{
			try
			{
				var resolvedTarget = directory.ResolveLinkTarget(returnFinalTarget: true);
				if (resolvedTarget != null && !string.IsNullOrWhiteSpace(resolvedTarget.FullName))
					return Path.GetFullPath(resolvedTarget.FullName);
			}
			catch
			{
			}

			return Path.GetFullPath(directory.FullName);
		}

		private static bool IsProjectedReparseTag(Winterop.ReparseTag tag)
		{
			return tag == Winterop.ReparseTag.ProjectedFS
				|| tag == Winterop.ReparseTag.ProjFSTombstone;
		}

		private static string BuildSkippedSmbReparseDirectoryMessage(UncPath reparsePath, Winterop.ReparseTag tag)
		{
			var tagDescription = $"{tag} (0x{(uint)tag:X8})";
			if (IsProjectedReparseTag(tag))
			{
				return
					$"Copy-TBOSmbItem skipped projected filesystem reparse directory '{reparsePath}' (tag {tagDescription}). Use -FollowReparse to traverse reparse directories.";
			}

			return
				$"Copy-TBOSmbItem skipped reparse directory '{reparsePath}' (tag {tagDescription}). Use -FollowReparse to traverse reparse directories.";
		}

		private static string BuildFollowingSmbReparseDirectoryMessage(UncPath reparsePath, Winterop.ReparseTag tag)
		{
			var tagDescription = $"{tag} (0x{(uint)tag:X8})";
			if (IsProjectedReparseTag(tag))
				return $"Copy-TBOSmbItem following projected filesystem reparse directory '{reparsePath}' (tag {tagDescription}).";

			return $"Copy-TBOSmbItem following reparse directory '{reparsePath}' (tag {tagDescription}).";
		}

		private static string BuildSkippedLocalReparseDirectoryMessage(string reparsePath)
		{
			return $"Copy-TBOSmbItem skipped reparse directory '{reparsePath}'. Use -FollowReparse to traverse reparse directories.";
		}

		private static string BuildFollowingLocalReparseDirectoryMessage(string reparsePath)
		{
			return $"Copy-TBOSmbItem following reparse directory '{reparsePath}'.";
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

		private void EnsureLocalDirectoryExists(string destinationPath)
		{
			if (Directory.Exists(destinationPath))
				return;
			if (File.Exists(destinationPath))
				throw new IOException($"Destination path '{destinationPath}' is not a directory.");
			if (!this.CreateDirectories.IsPresent)
				throw new IOException($"Destination directory '{destinationPath}' does not exist. Use -CreateDirectories to create it.");

			Directory.CreateDirectory(destinationPath);
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

		private static Smb2FileBasicInfoSnapshot GetLocalBasicInfo(FileSystemInfo sourceInfo)
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

		private void WriteVerboseSafe(string message)
		{
			if (string.IsNullOrWhiteSpace(message))
				return;

			try
			{
				this.WriteVerbose(message);
			}
			catch (PSInvalidOperationException)
			{
				// Ignore verbose writes that occur off the PowerShell pipeline thread.
			}
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

		private static async Task<Smb2Directory> OpenDirectoryAsync(
			Smb2Client smbClient,
			UncPath path,
			DateTime? timeWarpToken,
			uint desiredAccess,
			CancellationToken cancellationToken)
		{
			var createInfo = new Smb2CreateInfo
			{
				CreateDisposition = Smb2CreateDisposition.Open,
				DesiredAccess = desiredAccess,
				ShareAccess = Smb2ShareAccess.DefaultDirShare,
				ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
				CreateOptions = Smb2FileCreateOptions.Directory
					| Smb2FileCreateOptions.SynchronousIoNonalert
					| Smb2FileCreateOptions.OpenForBackupIntent,
				FileAttributes = Winterop.FileAttributes.None,
				RequestMaximalAccess = true,
				QueryOnDiskId = true,
				OplockLevel = Smb2OplockLevel.None
			};

			if (timeWarpToken.HasValue)
				createInfo.TimeWarpToken = timeWarpToken;

			return (Smb2Directory)await smbClient.CreateFileAsync(path, createInfo, FileAccess.Read, cancellationToken).ConfigureAwait(false);
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
