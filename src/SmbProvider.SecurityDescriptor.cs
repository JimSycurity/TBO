using System;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Provider;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using Titanis.Net;
using Titanis.Smb2;
using Titanis.Winterop.Security;
using Smb2AccessRights = Titanis.Smb2.Smb2FileAccessRights;
using Winterop = Titanis.Winterop;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public partial class SmbProvider
	{
		private const int DefaultSecurityDescriptorBufferSize = 8192;

		[SupportedOSPlatform("windows")]
		public void GetSecurityDescriptor(string path, AccessControlSections includeSections)
		{
			EnsureWindowsAclSupport("Get-Acl");
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("Path must be provided.", nameof(path));

			var snapshotPath = ResolveSnapshotPath(ResolveToUncPath(path, nameof(path)));
			var descriptor = this.BeginOperation(cancellationToken =>
				ReadSecurityDescriptor(snapshotPath, includeSections, cancellationToken));

			this.WriteSecurityDescriptorObject(descriptor, snapshotPath.OriginalPath.ToString());
		}

		[SupportedOSPlatform("windows")]
		public void SetSecurityDescriptor(string path, ObjectSecurity securityDescriptor)
		{
			EnsureWindowsAclSupport("Set-Acl");
			if (securityDescriptor == null)
				throw new ArgumentNullException(nameof(securityDescriptor));
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("Path must be provided.", nameof(path));

			var snapshotPath = ResolveSnapshotPath(ResolveToUncPath(path, nameof(path)));
			if (snapshotPath.HasTimeWarpToken)
				throw new NotSupportedException("Snapshot paths are read-only.");
			if (!this.ShouldProcess(snapshotPath.OriginalPath.ToString(), "Set security descriptor"))
				return;

			var raw = securityDescriptor.GetSecurityDescriptorBinaryForm();
			var descriptor = SecurityDescriptorHelpers.FromBytes(raw);
			var securityInfo = InferSecurityInfo(descriptor);

			this.BeginOperation(cancellationToken =>
			{
				WriteSecurityDescriptor(snapshotPath.ResolvedPath, descriptor, securityInfo, cancellationToken);
			});
		}

		[SupportedOSPlatform("windows")]
		public ObjectSecurity NewSecurityDescriptorFromPath(string path, AccessControlSections includeSections)
		{
			EnsureWindowsAclSupport("Get-Acl");
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("Path must be provided.", nameof(path));

			var snapshotPath = ResolveSnapshotPath(ResolveToUncPath(path, nameof(path)));
			return this.BeginOperation(cancellationToken =>
				ReadSecurityDescriptor(snapshotPath, includeSections, cancellationToken));
		}

		[SupportedOSPlatform("windows")]
		public ObjectSecurity NewSecurityDescriptorOfType(string type, AccessControlSections includeSections)
		{
			EnsureWindowsAclSupport("Get-Acl");
			return CreateObjectSecurity(type);
		}

		[SupportedOSPlatform("windows")]
		private ObjectSecurity ReadSecurityDescriptor(
			SnapshotPath snapshotPath,
			AccessControlSections sections,
			CancellationToken cancellationToken)
		{
			var securityInfo = MapSecurityInfo(sections);

			Smb2OpenFileObjectBase? file = null;
			try
			{
				var createInfo = new Smb2CreateInfo
				{
					CreateDisposition = Smb2CreateDisposition.Open,
					DesiredAccess = (uint)Smb2AccessRights.ReadControl,
					ShareAccess = Smb2ShareAccess.ReadWriteDelete,
					ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
					CreateOptions = Smb2FileCreateOptions.SynchronousIoNonalert,
					FileAttributes = Winterop.FileAttributes.Normal,
					TimeWarpToken = snapshotPath.TimeWarpToken
				};

				file = this.smb.SmbClient.CreateFileAsync(
					snapshotPath.ResolvedPath,
					createInfo,
					FileAccess.Read,
					cancellationToken).GetAwaiter().GetResult();

				var sd = file.GetSecurityAsync(
					securityInfo,
					DefaultSecurityDescriptorBufferSize,
					cancellationToken).GetAwaiter().GetResult();

				if (sd == null)
					throw new InvalidOperationException($"No security descriptor was returned for '{snapshotPath.OriginalPath}'.");

				var acl = CreateObjectSecurity(file.IsDirectory);
				acl.SetSecurityDescriptorBinaryForm(sd.ToByteArray(), sections);
				return acl;
			}
			finally
			{
				if (file != null)
					file.CloseAsync(cancellationToken).GetAwaiter().GetResult();
			}
		}

		[SupportedOSPlatform("windows")]
		private void WriteSecurityDescriptor(
			UncPath uncPath,
			SecurityDescriptor securityDescriptor,
			SecurityInfo securityInfo,
			CancellationToken cancellationToken)
		{
			Smb2OpenFileObjectBase? file = null;
			try
			{
				var desiredAccess = Smb2AccessRights.WriteDac | Smb2AccessRights.WriteOwner | Smb2AccessRights.ReadControl;
				if (securityInfo.HasFlag(SecurityInfo.Sacl))
					desiredAccess |= Smb2AccessRights.AccessSystemSecurity;

				var createInfo = new Smb2CreateInfo
				{
					CreateDisposition = Smb2CreateDisposition.Open,
					DesiredAccess = (uint)desiredAccess,
					ShareAccess = Smb2ShareAccess.ReadWriteDelete,
					ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
					CreateOptions = Smb2FileCreateOptions.SynchronousIoNonalert,
					FileAttributes = Winterop.FileAttributes.Normal
				};

				file = this.smb.SmbClient.CreateFileAsync(
					uncPath,
					createInfo,
					FileAccess.ReadWrite,
					cancellationToken).GetAwaiter().GetResult();

				file.SetSecurityAsync(
					securityDescriptor,
					securityInfo,
					cancellationToken).GetAwaiter().GetResult();
			}
			finally
			{
				if (file != null)
					file.CloseAsync(cancellationToken).GetAwaiter().GetResult();
			}
		}

		[SupportedOSPlatform("windows")]
		private static SecurityInfo MapSecurityInfo(AccessControlSections sections)
		{
			var securityInfo = SecurityInfo.None;
			if (sections.HasFlag(AccessControlSections.Owner))
				securityInfo |= SecurityInfo.Owner;
			if (sections.HasFlag(AccessControlSections.Group))
				securityInfo |= SecurityInfo.Group;
			if (sections.HasFlag(AccessControlSections.Access))
				securityInfo |= SecurityInfo.Dacl;
			if (sections.HasFlag(AccessControlSections.Audit))
				securityInfo |= SecurityInfo.Sacl;

			if (securityInfo == SecurityInfo.None)
				throw new ArgumentException("Sections must include at least one AccessControlSections flag.", nameof(sections));

			return securityInfo;
		}

		[SupportedOSPlatform("windows")]
		private static SecurityInfo InferSecurityInfo(SecurityDescriptor securityDescriptor)
		{
			if (securityDescriptor is null)
				throw new ArgumentNullException(nameof(securityDescriptor));

			var info = SecurityInfo.None;
			if (securityDescriptor.Owner != null)
				info |= SecurityInfo.Owner;
			if (securityDescriptor.Group != null)
				info |= SecurityInfo.Group;
			if (securityDescriptor.Dacl != null)
				info |= SecurityInfo.Dacl;
			if (securityDescriptor.Sacl != null)
				info |= SecurityInfo.Sacl;

			if (info == SecurityInfo.None)
				throw new ArgumentException("Security descriptor does not include any sections.", nameof(securityDescriptor));

			return info;
		}

		[SupportedOSPlatform("windows")]
		private static ObjectSecurity CreateObjectSecurity(string type)
		{
			if (!string.IsNullOrEmpty(type)
				&& type.Equals(SmbItemClasses.Directory, StringComparison.OrdinalIgnoreCase))
			{
				return new DirectorySecurity();
			}

			return new FileSecurity();
		}

		[SupportedOSPlatform("windows")]
		private static ObjectSecurity CreateObjectSecurity(bool isDirectory)
		{
			return isDirectory ? new DirectorySecurity() : new FileSecurity();
		}

		[SupportedOSPlatform("windows")]
		private static void EnsureWindowsAclSupport(string operation)
		{
			if (!OperatingSystem.IsWindows())
				throw new NotSupportedException($"{operation} is only supported on Windows for the TBO.Smb2 provider.");
		}

		private UncPath ResolveToUncPath(string path, string paramName)
		{
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("Path must be provided.", paramName);

			if (UncPath.TryParse(path, out var uncPath) && uncPath != null)
				return uncPath;

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

			if (providerInfo == null || !providerInfo.Name.Equals(ProviderName, StringComparison.OrdinalIgnoreCase))
				throw new ArgumentException($"Path must be a UNC path or a {ProviderName} PSDrive path: {path}", paramName);

			if (UncPath.TryParse(providerPath, out var resolvedUnc) && resolvedUnc != null)
				return resolvedUnc;

			throw new ArgumentException($"Resolved provider path is not a UNC path: {providerPath}", paramName);
		}
	}
}
