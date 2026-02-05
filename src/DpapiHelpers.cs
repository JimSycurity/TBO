using System;
using System.IO;
using System.Text;
using System.Threading;
using Titanis.Net;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal static class DpapiHelpers
	{
		internal static readonly byte[] DpapiMagic = new byte[]
		{
			0x01, 0x00, 0x00, 0x00, 0xD0, 0x8C, 0x9D, 0xDF, 0x01, 0x15,
			0xD1, 0x11, 0x8C, 0x7A, 0x00, 0xC0, 0x4F, 0xC2, 0x97, 0xEB
		};

		internal static int FindMagicOffset(ReadOnlySpan<byte> buffer)
		{
			if (buffer.Length < DpapiMagic.Length)
				return -1;

			return buffer.IndexOf(DpapiMagic);
		}

		internal static string NormalizeServerName(string? serverName)
		{
			return string.IsNullOrWhiteSpace(serverName)
				? string.Empty
				: serverName.TrimStart('\\');
		}

		internal static string NormalizeShareName(string? shareName)
		{
			if (string.IsNullOrWhiteSpace(shareName))
				return string.Empty;

			var trimmed = shareName.Trim();
			trimmed = trimmed.Trim('\\');
			return trimmed;
		}

		internal static byte[] ReadFileBytes(ISmbProviderInfo smb, UncPath path, CancellationToken cancellationToken)
		{
			var fileSystem = SmbFileSystemResolver.Resolve(smb);
			using var file = fileSystem.OpenFileRead(path, cancellationToken);
			using var stream = file.OpenRead();
			using var memory = new MemoryStream();
			stream.CopyTo(memory);
			return memory.ToArray();
		}

		internal static string? TryDecodeCleartext(byte[] payload)
		{
			if (payload.Length == 0)
				return null;

			if (payload.Length % 2 == 0)
			{
				try
				{
					var str = Encoding.Unicode.GetString(payload).TrimEnd('\0');
					if (IsLikelyText(str))
						return str;
				}
				catch
				{
				}
			}

			try
			{
				var str = Encoding.UTF8.GetString(payload).TrimEnd('\0');
				if (IsLikelyText(str))
					return str;
			}
			catch
			{
			}

			return null;
		}

		private static bool IsLikelyText(string? text)
		{
			if (string.IsNullOrWhiteSpace(text))
				return false;

			int asciiPrintable = 0;
			int controlCount = 0;
			int length = text.Length;

			for (int i = 0; i < length; i++)
			{
				char c = text[i];
				if (c == '\uFFFD')
					return false;
				if (char.IsControl(c) && c != '\r' && c != '\n' && c != '\t')
					controlCount++;
				if (c >= ' ' && c <= '~')
					asciiPrintable++;
			}

			if (controlCount > 0 || asciiPrintable == 0)
				return false;

			double asciiRatio = (double)asciiPrintable / length;
			return asciiRatio >= 0.6;
		}
	}
}
