using System;
using System.Security.AccessControl;
using System.Text;
using Titanis.Winterop.Security;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal enum SecurityDescriptorOutputFormat
	{
		Object,
		Sddl,
		Bytes,
		Windows
	}

	internal static class SecurityDescriptorHelpers
	{
		internal static SecurityDescriptorOutputFormat ResolveFormat(
			bool asSddl,
			bool asBytes,
			bool asWindows)
		{
			int selected = (asSddl ? 1 : 0) + (asBytes ? 1 : 0) + (asWindows ? 1 : 0);
			if (selected > 1)
				throw new ArgumentException("Only one security descriptor output format can be selected.");

			if (asSddl) return SecurityDescriptorOutputFormat.Sddl;
			if (asBytes) return SecurityDescriptorOutputFormat.Bytes;
			if (asWindows) return SecurityDescriptorOutputFormat.Windows;
			return SecurityDescriptorOutputFormat.Object;
		}

		internal static object Format(SecurityDescriptor descriptor, SecurityDescriptorOutputFormat format)
		{
			if (descriptor is null) throw new ArgumentNullException(nameof(descriptor));

			return format switch
			{
				SecurityDescriptorOutputFormat.Sddl => descriptor.ToSddlString(SecurityDescriptorSections.All),
				SecurityDescriptorOutputFormat.Bytes => descriptor.ToByteArray(),
				SecurityDescriptorOutputFormat.Windows => ToWindowsSecurityDescriptor(descriptor),
				_ => descriptor
			};
		}

		internal static SecurityDescriptor FromBytes(byte[] bytes)
		{
			if (bytes is null) throw new ArgumentNullException(nameof(bytes));
			return new SecurityDescriptor(bytes);
		}

		internal static SecurityDescriptor FromRegistryBinary(byte[] value)
		{
			if (value is null) throw new ArgumentNullException(nameof(value));

			try
			{
				return new SecurityDescriptor(value);
			}
			catch (Exception ex)
			{
				if (TryDecodeBase64(value, out var decoded))
					return new SecurityDescriptor(decoded);

				throw new ArgumentException("Value is not a valid security descriptor or base64-encoded security descriptor.", nameof(value), ex);
			}
		}

		internal static SecurityDescriptor FromRegistryBase64(string base64)
		{
			if (string.IsNullOrWhiteSpace(base64))
				throw new ArgumentException("Value cannot be null or empty.", nameof(base64));

			var bytes = Convert.FromBase64String(base64);
			return new SecurityDescriptor(bytes);
		}

		internal static byte[] ToRegistryBinary(SecurityDescriptor descriptor)
		{
			if (descriptor is null) throw new ArgumentNullException(nameof(descriptor));

			var base64 = Convert.ToBase64String(descriptor.ToByteArray());
			return Encoding.ASCII.GetBytes(base64);
		}

		internal static string ToRegistryBase64(SecurityDescriptor descriptor)
		{
			if (descriptor is null) throw new ArgumentNullException(nameof(descriptor));

			return Convert.ToBase64String(descriptor.ToByteArray());
		}

		internal static SecurityDescriptor FromSddl(string sddl)
		{
			if (string.IsNullOrWhiteSpace(sddl)) throw new ArgumentException("Value cannot be null or empty.", nameof(sddl));
			if (!OperatingSystem.IsWindows())
				throw new PlatformNotSupportedException("Windows security descriptor adapters are only supported on Windows.");

			var raw = new RawSecurityDescriptor(sddl);
			byte[] buffer = new byte[raw.BinaryLength];
			raw.GetBinaryForm(buffer, 0);
			return new SecurityDescriptor(buffer);
		}

		internal static SecurityDescriptor FromWindowsSecurityDescriptor(RawSecurityDescriptor raw)
		{
			if (raw is null) throw new ArgumentNullException(nameof(raw));
			if (!OperatingSystem.IsWindows())
				throw new PlatformNotSupportedException("Windows security descriptor adapters are only supported on Windows.");

			byte[] buffer = new byte[raw.BinaryLength];
			raw.GetBinaryForm(buffer, 0);
			return new SecurityDescriptor(buffer);
		}

		internal static SecurityDescriptor FromWindowsSecurityDescriptor(CommonSecurityDescriptor descriptor)
		{
			if (descriptor is null) throw new ArgumentNullException(nameof(descriptor));
			if (!OperatingSystem.IsWindows())
				throw new PlatformNotSupportedException("Windows security descriptor adapters are only supported on Windows.");

			byte[] buffer = new byte[descriptor.BinaryLength];
			descriptor.GetBinaryForm(buffer, 0);
			return new SecurityDescriptor(buffer);
		}

		private static RawSecurityDescriptor ToWindowsSecurityDescriptor(SecurityDescriptor descriptor)
		{
			if (!OperatingSystem.IsWindows())
				throw new PlatformNotSupportedException("Windows security descriptor adapters are only supported on Windows.");
			byte[] bytes = descriptor.ToByteArray();
			return new RawSecurityDescriptor(bytes, 0);
		}

		private static bool TryDecodeBase64(byte[] bytes, out byte[] decoded)
		{
			decoded = Array.Empty<byte>();
			if (bytes.Length == 0)
				return false;

			int length = bytes.Length;
			while (length > 0)
			{
				byte value = bytes[length - 1];
				if (value != 0 && !char.IsWhiteSpace((char)value))
					break;
				length--;
			}

			if (length == 0)
				return false;

			var text = Encoding.ASCII.GetString(bytes, 0, length).Trim();
			if (text.Length == 0)
				return false;

			byte[] buffer = new byte[(text.Length * 3) / 4 + 2];
			if (!Convert.TryFromBase64String(text, buffer, out int bytesWritten))
				return false;

			if (bytesWritten == 0)
				return false;

			decoded = buffer.AsSpan(0, bytesWritten).ToArray();
			return true;
		}
	}
}
