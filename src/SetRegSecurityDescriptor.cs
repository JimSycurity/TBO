using System;
using System.ComponentModel;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Threading;
using Titanis.Msrpc.Msrrp;
using Titanis.Winterop.Security;

namespace Titanis.Tbo.Smb2.PowerShell
{
	[Cmdlet(VerbsCommon.Set, "TBORegSecurityDescriptor", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High)]
	public sealed class SetTBORegSecurityDescriptor : TboRegCmdlet
	{
		private const RegistryAccessRights ReadControl = (RegistryAccessRights)0x00020000;
		private const RegistryAccessRights WriteDac = (RegistryAccessRights)0x00040000;
		private const RegistryAccessRights WriteOwner = (RegistryAccessRights)0x00080000;
		private const RegistryAccessRights AccessSystemSecurity = (RegistryAccessRights)0x01000000;
		private const RegistryAccessRights KeyAllAccess = (RegistryAccessRights)0x000F003F;

		[Parameter(Mandatory = true, Position = 1, ValueFromPipelineByPropertyName = true)]
		[Alias("KeyPath")]
		public string Path { get; set; } = string.Empty;

		[Parameter(Mandatory = true, Position = 2)]
		public object SecurityDescriptor { get; set; } = null!;

		[Parameter]
		public SecurityInfo Sections { get; set; } = SecurityInfo.Dacl;

		internal IRegistrySecurityDescriptorWriter SecurityDescriptorWriter { get; set; } = new RegistryKeySecurityDescriptorWriter();

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			if (this.Sections == SecurityInfo.None)
				throw new ArgumentException("Sections must include at least one SecurityInfo flag.", nameof(this.Sections));

			var parsedPath = ParseRegistryPath(this.Path, nameof(this.Path));
			var resolvedDescriptor = ResolveSecurityDescriptor(this.SecurityDescriptor);
			var securityInfo = ResolveSecurityInfo(resolvedDescriptor, this.Sections);
			var access = ResolveRegistryAccess(securityInfo);
			var rootAccess = ResolveRootRegistryAccess(parsedPath, access);

			if (!this.ShouldProcess($"{this.ServerName}:{parsedPath.KeyPath}", "Set registry security descriptor"))
				return;

			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				using var key = OpenRegistryKey(session.Client, parsedPath, access, rootAccess, cancellationToken);

				try
				{
					this.SecurityDescriptorWriter.SetSecurity(key, securityInfo, resolvedDescriptor, cancellationToken);
				}
				catch (Win32Exception ex) when (ex.NativeErrorCode == 5 && !securityInfo.HasFlag(SecurityInfo.Backup))
				{
					// Some servers appear to require BACKUP_SECURITY_INFORMATION to honor SeRestorePrivilege for SetKeySecurity.
					// Retry once with BACKUP_SECURITY_INFORMATION before escalating to a new handle with KEY_ALL_ACCESS.
					var backupInfo = securityInfo | SecurityInfo.Backup;
					this.LogVerbose(smb, $"Set-TBORegSecurityDescriptor access denied; retrying with {backupInfo}.");
					try
					{
						this.SecurityDescriptorWriter.SetSecurity(key, backupInfo, resolvedDescriptor, cancellationToken);
					}
					catch (Win32Exception ex2) when (ex2.NativeErrorCode == 5)
					{
						this.LogVerbose(smb, "Set-TBORegSecurityDescriptor still access denied; retrying with KEY_ALL_ACCESS handle.");
						using var keyAll = OpenRegistryKey(session.Client, parsedPath, KeyAllAccess, rootAccess, cancellationToken);
						this.SecurityDescriptorWriter.SetSecurity(keyAll, backupInfo, resolvedDescriptor, cancellationToken);
					}
				}
			});
		}

		private static RegistryAccessRights? ResolveRootRegistryAccess(RegistryPathSpec path, RegistryAccessRights access)
		{
			// MS-RRP root key opens (OpenHKLM/OpenHKU/etc.) do not support REG_OPTION_BACKUP_RESTORE.
			// Avoid requesting standard-write rights (WRITE_DAC/WRITE_OWNER/ACCESS_SYSTEM_SECURITY) on root opens,
			// since that can fail even though the actual target is a subkey opened with BackupRestore options.
			if (path.IsRoot)
				return null;

			var wow64 = access & (RegistryAccessRights.Wow64_Use64 | RegistryAccessRights.Wow64_Use32);
			return RegistryAccessRights.EnumerateSubkeys | RegistryAccessRights.QueryValue | ReadControl | wow64;
		}

		private static RegistryAccessRights ResolveRegistryAccess(SecurityInfo sections)
		{
			// Some servers appear to require at least one "registry" right (KEY_QUERY_VALUE, etc.)
			// even when the intended operation is purely standard-rights based (WRITE_DAC/WRITE_OWNER).
			// QueryValue is a safe baseline and avoids handle-access oddities.
			var access = ReadControl | RegistryAccessRights.QueryValue;
			if (sections.HasFlag(SecurityInfo.Dacl))
				access |= WriteDac;
			if (sections.HasFlag(SecurityInfo.Owner) || sections.HasFlag(SecurityInfo.Group))
				access |= WriteOwner;
			if (sections.HasFlag(SecurityInfo.Sacl))
				access |= AccessSystemSecurity;

			return access;
		}

		private static SecurityDescriptor ResolveSecurityDescriptor(object input)
		{
			if (input is PSObject psObject)
				input = psObject.BaseObject;

			switch (input)
			{
				case SecurityDescriptor descriptor:
					return descriptor;
				case byte[] bytes:
					return SecurityDescriptorHelpers.FromBytes(bytes);
				case string sddl:
					if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
						throw new NotSupportedException("SDDL input is only supported on Windows. Provide a byte[] or Titanis SecurityDescriptor instead.");
					return SecurityDescriptorHelpers.FromSddl(sddl);
				case RawSecurityDescriptor rawDescriptor:
					if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
						throw new NotSupportedException("Windows security descriptor types are only supported on Windows. Provide a byte[] or Titanis SecurityDescriptor instead.");
					return SecurityDescriptorHelpers.FromWindowsSecurityDescriptor(rawDescriptor);
				case CommonSecurityDescriptor commonDescriptor:
					if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
						throw new NotSupportedException("Windows security descriptor types are only supported on Windows. Provide a byte[] or Titanis SecurityDescriptor instead.");
					return SecurityDescriptorHelpers.FromWindowsSecurityDescriptor(commonDescriptor);
				case GenericSecurityDescriptor genericDescriptor:
					if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
						throw new NotSupportedException("Windows security descriptor types are only supported on Windows. Provide a byte[] or Titanis SecurityDescriptor instead.");
					var buffer = new byte[genericDescriptor.BinaryLength];
					genericDescriptor.GetBinaryForm(buffer, 0);
					return SecurityDescriptorHelpers.FromBytes(buffer);
				default:
					throw new ArgumentException("SecurityDescriptor must be a Titanis SecurityDescriptor, SDDL string (Windows only), raw byte array, or Windows security descriptor.", nameof(input));
			}
		}

		private static SecurityInfo ResolveSecurityInfo(SecurityDescriptor securityDescriptor, SecurityInfo requestedSections)
		{
			if (securityDescriptor is null) throw new ArgumentNullException(nameof(securityDescriptor));

			if (requestedSections == SecurityInfo.None)
				throw new ArgumentException("Sections must include at least one SecurityInfo flag.", nameof(requestedSections));

			if (requestedSections.HasFlag(SecurityInfo.Owner) && securityDescriptor.Owner == null)
				throw new ArgumentException("Security descriptor does not include an owner section.", nameof(securityDescriptor));
			if (requestedSections.HasFlag(SecurityInfo.Group) && securityDescriptor.Group == null)
				throw new ArgumentException("Security descriptor does not include a group section.", nameof(securityDescriptor));
			if (requestedSections.HasFlag(SecurityInfo.Dacl) && securityDescriptor.Dacl == null)
				throw new ArgumentException("Security descriptor does not include a DACL.", nameof(securityDescriptor));
			if (requestedSections.HasFlag(SecurityInfo.Sacl) && securityDescriptor.Sacl == null)
				throw new ArgumentException("Security descriptor does not include a SACL.", nameof(securityDescriptor));

			return requestedSections;
		}
	}
}
