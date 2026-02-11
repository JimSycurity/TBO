using System;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Threading;
using Titanis.Msrpc.Msrrp;
using Titanis.Winterop.Security;

namespace Titanis.Tbo.Smb2.PowerShell
{
	[Cmdlet(VerbsCommon.Get, "TBORegSecurityDescriptor")]
	public sealed class GetTBORegSecurityDescriptor : TboRegCmdlet
	{
		private const RegistryAccessRights ReadControl = (RegistryAccessRights)0x00020000;
		private const RegistryAccessRights AccessSystemSecurity = (RegistryAccessRights)0x01000000;

		[Parameter(Mandatory = true, Position = 1, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
		[Alias("KeyPath")]
		public string Path { get; set; } = string.Empty;

		[Parameter]
		public SwitchParameter AsSddl { get; set; }

		[Parameter]
		public SwitchParameter AsBytes { get; set; }

		[Parameter]
		public SwitchParameter AsWindows { get; set; }

		[Parameter]
		public SecurityInfo Sections { get; set; } = SecurityInfo.Owner | SecurityInfo.Group | SecurityInfo.Dacl;

		protected override void ProcessRecord(ISmbProviderInfo smb, CancellationToken cancellationToken)
		{
			if (this.AsWindows.IsPresent && !RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
				throw new NotSupportedException("AsWindows is only supported on Windows.");

			int formatFlags = (this.AsSddl.IsPresent ? 1 : 0) + (this.AsBytes.IsPresent ? 1 : 0) + (this.AsWindows.IsPresent ? 1 : 0);
			if (formatFlags > 1)
				throw new ArgumentException("Only one of -AsSddl, -AsBytes, or -AsWindows can be specified.");

			if (this.Sections == SecurityInfo.None)
				throw new ArgumentException("Sections must include at least one SecurityInfo flag.", nameof(this.Sections));

			var format = SecurityDescriptorHelpers.ResolveFormat(this.AsSddl, this.AsBytes, this.AsWindows);
			var parsedPath = ParseRegistryPath(this.Path, nameof(this.Path));

			ExecuteRegistryOperation(smb, cancellationToken, session =>
			{
				var access = ResolveRegistryAccess(this.Sections);
				var rootAccess = ResolveRootRegistryAccess(parsedPath, access);
				using var key = OpenRegistryKey(session.Client, parsedPath, access, rootAccess, cancellationToken);

				var sdBytes = key.QuerySecurity(this.Sections, cancellationToken).GetAwaiter().GetResult();
				if (sdBytes.Length == 0)
				{
					this.LogWarning(smb, $"No security descriptor was returned for '{parsedPath.KeyPath}'.");
					return;
				}

				var descriptor = SecurityDescriptorHelpers.FromBytes(sdBytes);
				this.WriteObject(SecurityDescriptorHelpers.Format(descriptor, format));
			});
		}

		private static RegistryAccessRights ResolveRegistryAccess(SecurityInfo sections)
		{
			var access = RegistryAccessRights.QueryValue | RegistryAccessRights.EnumerateSubkeys | ReadControl;
			if (sections.HasFlag(SecurityInfo.Sacl)
				|| sections.HasFlag(SecurityInfo.ProtectedSacl)
				|| sections.HasFlag(SecurityInfo.UnprotectedSacl))
			{
				access |= AccessSystemSecurity;
			}

			return access;
		}

		private static RegistryAccessRights? ResolveRootRegistryAccess(RegistryPathSpec path, RegistryAccessRights access)
		{
			if (path.IsRoot)
				return null;

			var wow64 = access & (RegistryAccessRights.Wow64_Use64 | RegistryAccessRights.Wow64_Use32);
			return RegistryAccessRights.EnumerateSubkeys | RegistryAccessRights.QueryValue | ReadControl | wow64;
		}
	}
}
