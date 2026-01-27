using System;
using System.ComponentModel;

namespace Titanis.Tbo.Smb2.PowerShell
{
	[TypeConverter(typeof(NtlmHashInputConverter))]
	internal sealed class NtlmHashInput
	{
		internal NtlmHashInput(byte[]? lmHash, byte[] ntHash, string? originalText)
		{
			this.LmHash = lmHash;
			this.NtHash = ntHash ?? throw new ArgumentNullException(nameof(ntHash));
			this.OriginalText = originalText;
		}

		public byte[]? LmHash { get; }
		public byte[] NtHash { get; }
		public string? OriginalText { get; }

		public static NtlmHashInput Parse(string text)
		{
			if (text is null)
				throw new ArgumentNullException(nameof(text));

			var trimmed = text.Trim();
			if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
				trimmed = trimmed.Substring(2);

			var colonIndex = trimmed.IndexOf(':');
			if (colonIndex >= 0)
			{
				var parts = trimmed.Split(new[] { ':' }, 2, StringSplitOptions.None);
				var lmText = parts[0];
				var ntText = parts.Length > 1 ? parts[1] : string.Empty;

				byte[]? lmBytes = null;
				if (!string.IsNullOrEmpty(lmText))
					lmBytes = ParseHashBytes(lmText, "LM");

				if (string.IsNullOrEmpty(ntText))
					throw new ArgumentException("NT hash portion is required when using LM:NT format.", nameof(text));

				var ntBytes = ParseHashBytes(ntText, "NT");
				return new NtlmHashInput(lmBytes, ntBytes, text);
			}

			var bytes = Titanis.BinaryHelper.ParseHexString(trimmed.AsSpan());
			return FromBytes(bytes, text);
		}

		internal static NtlmHashInput FromBytes(byte[] bytes, string? originalText)
		{
			if (bytes is null)
				throw new ArgumentNullException(nameof(bytes));

			if (bytes.Length == 16)
				return new NtlmHashInput(null, bytes, originalText);

			if (bytes.Length == 32)
			{
				var lm = new byte[16];
				var nt = new byte[16];
				Array.Copy(bytes, 0, lm, 0, 16);
				Array.Copy(bytes, 16, nt, 0, 16);
				return new NtlmHashInput(lm, nt, originalText);
			}

			throw new ArgumentException("NTLM hash must be 16 bytes (NT) or 32 bytes (LM+NT).", nameof(bytes));
		}

		private static byte[] ParseHashBytes(string text, string label)
		{
			var bytes = Titanis.BinaryHelper.ParseHexString(text.AsSpan());
			if (bytes.Length != 16)
				throw new ArgumentException($"{label} hash must be 16 bytes (32 hex characters).");
			return bytes;
		}
	}

	internal sealed class NtlmHashInputConverter : TypeConverter
	{
		public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType)
			=> sourceType == typeof(string) || sourceType == typeof(byte[]);

		public override bool CanConvertTo(ITypeDescriptorContext context, Type destinationType)
			=> destinationType == typeof(NtlmHashInput);

		public override object ConvertFrom(ITypeDescriptorContext context, System.Globalization.CultureInfo culture, object value)
		{
			if (value is null)
				throw new ArgumentNullException(nameof(value));

			if (value is string text)
				return NtlmHashInput.Parse(text);

			if (value is byte[] bytes)
				return NtlmHashInput.FromBytes(bytes, null);

			throw new ArgumentException($"Cannot convert object of type {value.GetType().FullName} to {nameof(NtlmHashInput)}.");
		}
	}
}
