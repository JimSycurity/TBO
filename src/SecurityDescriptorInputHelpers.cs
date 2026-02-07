using System;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using Titanis.Winterop.Security;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal static class SecurityDescriptorInputHelpers
	{
		internal static SecurityDescriptor ResolveSecurityDescriptor(object input, bool allowRegistryBinaryBytes)
		{
			if (input is PSObject psObject)
				input = psObject.BaseObject;

			switch (input)
			{
				case SecurityDescriptor descriptor:
					return descriptor;
				case byte[] bytes:
					try
					{
						// Default interpretation is "raw" security descriptor bytes.
						return SecurityDescriptorHelpers.FromBytes(bytes);
					}
					catch when (allowRegistryBinaryBytes)
					{
						// Some callers work with the REG_BINARY "security descriptor" format stored in the registry.
						// Support both, since the cmdlets expose both representations depending on the scenario.
						return SecurityDescriptorHelpers.FromRegistryBinary(bytes);
					}
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

		internal static SecurityInfo ResolveSecurityInfo(SecurityDescriptor securityDescriptor, SecurityInfo requestedSections)
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

		internal static byte[] ResolveBinarySecurityDescriptorBytes(object input)
		{
			if (input is PSObject psObject)
				input = psObject.BaseObject;

			switch (input)
			{
				case byte[] bytes:
					// Treat byte[] inputs as a binary security descriptor. This enables round-trip
					// writes even when the portable SecurityDescriptor parser does not understand
					// the descriptor (for example, custom SACL ACEs).
					return bytes;
				case SecurityDescriptor descriptor:
					return descriptor.ToByteArray();
				case string sddl:
					if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
						throw new NotSupportedException("SDDL input is only supported on Windows. Provide a byte[] or Titanis SecurityDescriptor instead.");
					return ToBytes(new RawSecurityDescriptor(sddl));
				case RawSecurityDescriptor rawDescriptor:
					if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
						throw new NotSupportedException("Windows security descriptor types are only supported on Windows. Provide a byte[] or Titanis SecurityDescriptor instead.");
					return ToBytes(rawDescriptor);
				case CommonSecurityDescriptor commonDescriptor:
					if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
						throw new NotSupportedException("Windows security descriptor types are only supported on Windows. Provide a byte[] or Titanis SecurityDescriptor instead.");
					return ToBytes(commonDescriptor);
				case GenericSecurityDescriptor genericDescriptor:
					if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
						throw new NotSupportedException("Windows security descriptor types are only supported on Windows. Provide a byte[] or Titanis SecurityDescriptor instead.");
					return ToBytes(genericDescriptor);
				default:
					throw new ArgumentException("SecurityDescriptor must be a Titanis SecurityDescriptor, SDDL string (Windows only), raw byte array, or Windows security descriptor.", nameof(input));
			}
		}

		private static byte[] ToBytes(GenericSecurityDescriptor descriptor)
		{
			var buffer = new byte[descriptor.BinaryLength];
			descriptor.GetBinaryForm(buffer, 0);
			return buffer;
		}
	}
}
