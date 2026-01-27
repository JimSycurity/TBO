using System;
using System.Security.AccessControl;
using Titanis.Winterop.Security;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public static class TBOSD
	{
		public static SecurityDescriptor FromRegistryBinary(byte[] value)
			=> SecurityDescriptorHelpers.FromRegistryBinary(value);

		public static RawSecurityDescriptor FromRegistryBinaryAsWindows(byte[] value)
		{
			if (!OperatingSystem.IsWindows())
				throw new PlatformNotSupportedException("Windows security descriptors are only supported on Windows.");
			if (value is null)
				throw new ArgumentNullException(nameof(value));

			var descriptor = SecurityDescriptorHelpers.FromRegistryBinary(value);
			return new RawSecurityDescriptor(descriptor.ToByteArray(), 0);
		}

		public static SecurityDescriptor FromRegistryBase64(string base64)
			=> SecurityDescriptorHelpers.FromRegistryBase64(base64);

		public static byte[] ToRegistryBinary(SecurityDescriptor descriptor)
			=> SecurityDescriptorHelpers.ToRegistryBinary(descriptor);

		public static string ToRegistryBase64(SecurityDescriptor descriptor)
			=> SecurityDescriptorHelpers.ToRegistryBase64(descriptor);
	}
}
