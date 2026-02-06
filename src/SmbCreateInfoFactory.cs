using System;
using Titanis.Smb2;
using Winterop = Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal static class SmbCreateInfoFactory
	{
		private const Smb2FileCreateOptions RequiredCreateOptions =
			Smb2FileCreateOptions.OpenForBackupIntent;

		private static Smb2FileCreateOptions ApplyRequiredOptions(Smb2FileCreateOptions options)
			=> options | RequiredCreateOptions;

		private static Smb2CreateInfo CreateOpenInfo(
			Smb2CreateDisposition disposition,
			uint desiredAccess,
			Smb2ShareAccess shareAccess,
			Winterop.FileAttributes fileAttributes,
			DateTime? timeWarpToken,
			Smb2FileCreateOptions createOptions,
			bool synchronousIo,
			Smb2ImpersonationLevel impersonationLevel = Smb2ImpersonationLevel.Impersonation)
		{
			if (synchronousIo)
				createOptions |= Smb2FileCreateOptions.SynchronousIoNonalert;

			return new Smb2CreateInfo
			{
				CreateDisposition = disposition,
				DesiredAccess = desiredAccess,
				ShareAccess = shareAccess,
				ImpersonationLevel = impersonationLevel,
				CreateOptions = ApplyRequiredOptions(createOptions),
				FileAttributes = fileAttributes,
				TimeWarpToken = timeWarpToken
			};
		}

		internal static Smb2CreateInfo CreateOpenDirectoryInfo(DateTime? timeWarpToken)
		{
			var info = CreateOpenInfo(
				Smb2CreateDisposition.Open,
				(uint)Smb2FileAccessRights.DefaultOpenDirAccess,
				Smb2ShareAccess.DefaultDirShare,
				Winterop.FileAttributes.None,
				timeWarpToken,
				Smb2FileCreateOptions.Directory,
				synchronousIo: true);

			info.Priority = Smb2Priority.OpenDir;
			info.RequestMaximalAccess = true;
			info.QueryOnDiskId = true;
			info.OplockLevel = Smb2OplockLevel.None;
			return info;
		}

		internal static Smb2CreateInfo CreateOpenReadFileInfo(
			DateTime? timeWarpToken,
			bool nonDirectory,
			bool openReparsePoint,
			Smb2ShareAccess shareAccess = Smb2ShareAccess.Read,
			uint? desiredAccess = null,
			Winterop.FileAttributes fileAttributes = Winterop.FileAttributes.Normal)
		{
			var options = Smb2FileCreateOptions.None;
			if (nonDirectory)
				options |= Smb2FileCreateOptions.NonDirectory;
			if (openReparsePoint)
				options |= Smb2FileCreateOptions.OpenReparsePoint;

			return CreateOpenInfo(
				Smb2CreateDisposition.Open,
				desiredAccess ?? (uint)Smb2FileAccessRights.DefaultOpenReadAccess,
				shareAccess,
				fileAttributes,
				timeWarpToken,
				options,
				synchronousIo: true);
		}

		internal static Smb2CreateInfo CreateOpenReparseInfo(DateTime? timeWarpToken)
		{
			return CreateOpenInfo(
				Smb2CreateDisposition.Open,
				(uint)(Smb2FileAccessRights.ReadAttributes | Smb2FileAccessRights.ReadEa),
				Smb2ShareAccess.ReadWriteDelete,
				Winterop.FileAttributes.None,
				timeWarpToken,
				Smb2FileCreateOptions.OpenReparsePoint | Smb2FileCreateOptions.OpenNoRecall,
				synchronousIo: true);
		}

		internal static Smb2CreateInfo CreateContentWriteInfo(
			Smb2CreateDisposition disposition,
			DateTime? timeWarpToken)
		{
			return CreateOpenInfo(
				disposition,
				(uint)Smb2FileAccessRights.DefaultCreateAccess,
				Smb2ShareAccess.ReadWrite,
				Winterop.FileAttributes.Normal,
				timeWarpToken,
				Smb2FileCreateOptions.NonDirectory,
				synchronousIo: true);
		}

		internal static Smb2CreateInfo CreateNewFileInfo()
		{
			return CreateOpenInfo(
				Smb2CreateDisposition.Create,
				(uint)Smb2FileAccessRights.DefaultCreateAccess,
				Smb2ShareAccess.ReadWrite,
				Winterop.FileAttributes.Normal,
				timeWarpToken: null,
				Smb2FileCreateOptions.NonDirectory,
				synchronousIo: true);
		}

		internal static Smb2CreateInfo CreateNewDirectoryInfo()
		{
			var info = CreateOpenInfo(
				Smb2CreateDisposition.Create,
				(uint)Smb2FileAccessRights.DefaultCreateDirAccess,
				Smb2ShareAccess.ReadWrite,
				Winterop.FileAttributes.Normal,
				timeWarpToken: null,
				Smb2FileCreateOptions.Directory | Smb2FileCreateOptions.OpenReparsePoint,
				synchronousIo: true);

			info.Priority = Smb2Priority.CreateDir;
			return info;
		}

		internal static Smb2CreateInfo CreateReparseDirectoryInfo()
		{
			var info = CreateOpenInfo(
				Smb2CreateDisposition.OpenIf,
				(uint)Smb2FileAccessRights.WriteAttributes,
				Smb2ShareAccess.ReadWriteDelete,
				Winterop.FileAttributes.Normal,
				timeWarpToken: null,
				Smb2FileCreateOptions.Directory | Smb2FileCreateOptions.OpenReparsePoint,
				synchronousIo: false);

			info.OplockLevel = Smb2OplockLevel.None;
			info.RequestMaximalAccess = true;
			info.QueryOnDiskId = true;
			return info;
		}

		internal static Smb2CreateInfo CreateReparseFileInfo()
		{
			var info = CreateOpenInfo(
				Smb2CreateDisposition.OpenIf,
				(uint)Smb2FileAccessRights.WriteAttributes,
				Smb2ShareAccess.ReadWriteDelete,
				Winterop.FileAttributes.Normal,
				timeWarpToken: null,
				Smb2FileCreateOptions.NonDirectory | Smb2FileCreateOptions.OpenReparsePoint,
				synchronousIo: false);

			info.OplockLevel = Smb2OplockLevel.None;
			info.RequestMaximalAccess = true;
			info.QueryOnDiskId = true;
			return info;
		}
	}
}
