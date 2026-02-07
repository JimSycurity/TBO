using System;
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

			if (!this.ShouldProcess($"{this.ServerName}:{parsedPath.KeyPath}", "Set registry security descriptor"))
				return;

			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				using var key = OpenRegistryKey(session.Client, parsedPath, access, cancellationToken);
				this.SecurityDescriptorWriter.SetSecurity(key, securityInfo, resolvedDescriptor, cancellationToken);
			});
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
