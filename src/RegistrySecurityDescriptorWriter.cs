using System;
using System.Threading;
using Titanis.Msrpc.Msrrp;
using Titanis.Winterop.Security;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal interface IRegistrySecurityDescriptorWriter
	{
		void SetSecurity(RegistryKey key, SecurityInfo sections, SecurityDescriptor securityDescriptor, CancellationToken cancellationToken);
	}

	internal sealed class RegistryKeySecurityDescriptorWriter : IRegistrySecurityDescriptorWriter
	{
		public void SetSecurity(RegistryKey key, SecurityInfo sections, SecurityDescriptor securityDescriptor, CancellationToken cancellationToken)
		{
			if (key == null) throw new ArgumentNullException(nameof(key));
			if (securityDescriptor == null) throw new ArgumentNullException(nameof(securityDescriptor));

			key.SetSecurity(sections, securityDescriptor.ToByteArray(), cancellationToken).GetAwaiter().GetResult();
		}
	}
}
