using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using Titanis.Net;
using Titanis.Smb2;
using Titanis.Winterop.Security;
using SmbFileAccessRights = Titanis.Smb2.Smb2FileAccessRights;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public interface ISmbFileSystem
	{
		ISmbDirectory OpenDirectory(UncPath path, CancellationToken cancellationToken);
		ISmbFile OpenFileRead(UncPath path, CancellationToken cancellationToken);
	}

	public interface ISmbDirectory : IDisposable
	{
		IReadOnlyList<Smb2DirEntry> QueryEntries(
			string pattern,
			Smb2Directory.Smb2DirQueryOptions options,
			SecurityInfo securityInfo,
			int bufferSize,
			CancellationToken cancellationToken);
	}

	public interface ISmbFile : IDisposable
	{
		Stream OpenRead();
		long Length { get; }
	}

	internal interface ISmbFileSystemProvider
	{
		ISmbFileSystem? FileSystem { get; }
	}

	internal sealed class SmbFileSystemResolver
	{
		internal static ISmbFileSystem Resolve(ISmbProviderInfo smb)
		{
			if (smb is ISmbFileSystemProvider provider && provider.FileSystem != null)
				return provider.FileSystem;

			return new SmbClientFileSystem(smb.SmbClient);
		}
	}

	internal sealed class SmbClientFileSystem : ISmbFileSystem
	{
		private readonly Smb2Client _client;

		public SmbClientFileSystem(Smb2Client client)
		{
			this._client = client ?? throw new ArgumentNullException(nameof(client));
		}

		public ISmbDirectory OpenDirectory(UncPath path, CancellationToken cancellationToken)
		{
			var dir = (Smb2Directory)this._client.CreateFileAsync(path, new Smb2CreateInfo
			{
				CreateDisposition = Smb2CreateDisposition.Open,
				Priority = Smb2Priority.OpenDir,
				DesiredAccess = (uint)SmbFileAccessRights.DefaultOpenDirAccess,
				ShareAccess = Smb2ShareAccess.DefaultDirShare,
				FileAttributes = Titanis.Winterop.FileAttributes.None,
				CreateOptions = Smb2FileCreateOptions.Directory
					| Smb2FileCreateOptions.SynchronousIoNonalert
					| Smb2FileCreateOptions.OpenForBackupIntent,
				ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
				RequestMaximalAccess = true,
				QueryOnDiskId = true,
				OplockLevel = Smb2OplockLevel.None
			}, FileAccess.Read, cancellationToken).GetAwaiter().GetResult();

			return new SmbDirectoryAdapter(dir);
		}

		public ISmbFile OpenFileRead(UncPath path, CancellationToken cancellationToken)
		{
			var file = (Smb2OpenFile)this._client.CreateFileAsync(path, new Smb2CreateInfo
			{
				CreateDisposition = Smb2CreateDisposition.Open,
				DesiredAccess = (uint)SmbFileAccessRights.DefaultOpenReadAccess,
				ShareAccess = Smb2ShareAccess.Read,
				ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
				CreateOptions = Smb2FileCreateOptions.NonDirectory
					| Smb2FileCreateOptions.SynchronousIoNonalert
					| Smb2FileCreateOptions.OpenForBackupIntent,
				FileAttributes = Titanis.Winterop.FileAttributes.Normal,
				RequestMaximalAccess = true
			}, FileAccess.Read, cancellationToken).GetAwaiter().GetResult();

			return new SmbFileAdapter(file);
		}
	}

	internal sealed class SmbDirectoryAdapter : ISmbDirectory
	{
		private readonly Smb2Directory _directory;

		public SmbDirectoryAdapter(Smb2Directory directory)
		{
			this._directory = directory ?? throw new ArgumentNullException(nameof(directory));
		}

		public IReadOnlyList<Smb2DirEntry> QueryEntries(
			string pattern,
			Smb2Directory.Smb2DirQueryOptions options,
			SecurityInfo securityInfo,
			int bufferSize,
			CancellationToken cancellationToken)
		{
			return this._directory.QueryDirAsync(pattern, options, securityInfo, bufferSize, cancellationToken)
				.GetAwaiter().GetResult();
		}

		public void Dispose()
		{
			this._directory.CloseAsync(CancellationToken.None).GetAwaiter().GetResult();
		}
	}

	internal sealed class SmbFileAdapter : ISmbFile
	{
		private readonly Smb2OpenFile _file;

		public SmbFileAdapter(Smb2OpenFile file)
		{
			this._file = file ?? throw new ArgumentNullException(nameof(file));
		}

		public Stream OpenRead()
		{
			return this._file.GetStream(false);
		}

		public long Length => this._file.Length;

		public void Dispose()
		{
			this._file.CloseAsync(CancellationToken.None).GetAwaiter().GetResult();
		}
	}
}
