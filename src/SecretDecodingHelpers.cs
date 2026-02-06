using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Titanis;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed record SecretDecodeOptions
	{
		public int MinTextLength { get; init; } = 1;
		public int MinAsciiCount { get; init; } = 1;
		public double MinAsciiRatio { get; init; } = 0.6;
		public double MinPrintableRatio { get; init; } = 0.8;
		public double MaxNonAsciiRatio { get; init; } = 1.0;
		public bool RejectReplacementChar { get; init; } = true;
		public bool AllowControlChars { get; init; } = false;
		public bool AllowFragmentFallback { get; init; } = false;
		public bool IncludeHexOnFailure { get; init; } = false;

		public int MinFragmentLength { get; init; } = 6;
		public int MaxFragmentLength { get; init; } = 256;
		public int MaxFragments { get; init; } = 12;
	}

	public sealed record SecretDecodeResult
	{
		public string? Text { get; init; }
		public string? Hex { get; init; }
		public string? Encoding { get; init; }
		public double? Confidence { get; init; }
		public string? FailureReason { get; init; }
		public int BytesLength { get; init; }

		public bool Success => !string.IsNullOrEmpty(this.Text) || !string.IsNullOrEmpty(this.Hex);
	}

	public static class SecretDecoding
	{
		private const string EncodingUtf16 = "UTF-16LE";
		private const string EncodingUtf8 = "UTF-8";
		private const string EncodingHex = "HEX";
		private const string EncodingFragments = "FRAGMENTS";

		public static SecretDecodeResult TryDecode(byte[] payload, SecretDecodeOptions? options = null, Action<string>? log = null)
		{
			options ??= new SecretDecodeOptions();
			log ??= _ => { };

			if (payload == null || payload.Length == 0)
			{
				return new SecretDecodeResult
				{
					BytesLength = payload?.Length ?? 0,
					FailureReason = "Payload is empty."
				};
			}

			var failures = new List<string>();

			if (TryDecodeUtf16(payload, options, out var utf16Text, out var utf16Confidence, out var utf16Failure))
			{
				return new SecretDecodeResult
				{
					Text = utf16Text,
					Encoding = EncodingUtf16,
					Confidence = utf16Confidence,
					BytesLength = payload.Length
				};
			}

			if (!string.IsNullOrWhiteSpace(utf16Failure))
			{
				failures.Add($"UTF-16: {utf16Failure}");
				log($"SecretDecoding UTF-16 rejected: {utf16Failure}");
			}

			if (TryDecodeUtf8(payload, options, out var utf8Text, out var utf8Confidence, out var utf8Failure))
			{
				return new SecretDecodeResult
				{
					Text = utf8Text,
					Encoding = EncodingUtf8,
					Confidence = utf8Confidence,
					BytesLength = payload.Length
				};
			}

			if (!string.IsNullOrWhiteSpace(utf8Failure))
			{
				failures.Add($"UTF-8: {utf8Failure}");
				log($"SecretDecoding UTF-8 rejected: {utf8Failure}");
			}

			if (options.AllowFragmentFallback)
			{
				if (TryExtractReadableFragments(payload, options, out var fragmentText, out var fragmentConfidence))
				{
					return new SecretDecodeResult
					{
						Text = fragmentText,
						Encoding = EncodingFragments,
						Confidence = fragmentConfidence,
						BytesLength = payload.Length
					};
				}

				log("SecretDecoding fragment fallback did not produce readable text.");
			}

			var failureReason = failures.Count == 0
				? "No suitable text decode found."
				: string.Join("; ", failures);

			if (options.IncludeHexOnFailure)
			{
				return new SecretDecodeResult
				{
					Hex = payload.ToHexString(),
					Encoding = EncodingHex,
					Confidence = 0.0,
					FailureReason = failureReason,
					BytesLength = payload.Length
				};
			}

			return new SecretDecodeResult
			{
				FailureReason = failureReason,
				BytesLength = payload.Length
			};
		}

		public static bool TryDecodeUtf16(byte[] payload, out string text)
		{
			return TryDecodeUtf16(payload, new SecretDecodeOptions(), out text, out _, out _);
		}

		public static bool TryDecodeUtf8(byte[] payload, out string text)
		{
			return TryDecodeUtf8(payload, new SecretDecodeOptions(), out text, out _, out _);
		}

		public static bool TryReadLengthPrefixedUtf16(ReadOnlySpan<byte> payload, ref int offset, out string text)
		{
			text = string.Empty;
			if (offset < 0 || offset + sizeof(uint) > payload.Length)
				return false;

			uint lengthValue = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(offset, sizeof(uint)));
			if (lengthValue > int.MaxValue)
				return false;

			int length = (int)lengthValue;
			int start = offset + sizeof(uint);
			if (!TryReadFixedUtf16Internal(payload, start, length, out text, out var bytesConsumed))
				return false;

			offset = start + bytesConsumed;
			return true;
		}

		public static bool TryReadFixedUtf16(ReadOnlySpan<byte> payload, int length, out string text)
		{
			return TryReadFixedUtf16(payload, 0, length, out text);
		}

		public static bool TryReadFixedUtf16(ReadOnlySpan<byte> payload, int offset, int length, out string text)
		{
			return TryReadFixedUtf16Internal(payload, offset, length, out text, out _);
		}

		public static string? TryExtractReadableFragments(byte[] payload, SecretDecodeOptions? options = null)
		{
			if (payload == null || payload.Length == 0)
				return null;

			options ??= new SecretDecodeOptions();
			return TryExtractReadableFragments(payload, options, out var fragmentText, out _)
				? fragmentText
				: null;
		}

		public static string? ToHexIfBinary(byte[] payload)
		{
			if (payload == null || payload.Length == 0)
				return null;

			return payload.ToHexString();
		}

		private static bool TryDecodeUtf16(
			byte[] payload,
			SecretDecodeOptions options,
			out string text,
			out double confidence,
			out string? failure)
		{
			text = string.Empty;
			confidence = 0.0;
			failure = null;

			if (payload.Length == 0)
			{
				failure = "Payload empty";
				return false;
			}

			if (payload.Length % 2 != 0)
			{
				failure = "Payload length is not UTF-16 aligned";
				return false;
			}

			string decoded;
			try
			{
				decoded = Encoding.Unicode.GetString(payload).TrimEnd('\0');
			}
			catch (Exception ex)
			{
				failure = ex.Message;
				return false;
			}

			if (!TryEvaluateText(decoded, options, out var evaluation, out failure))
				return false;

			text = decoded;
			confidence = ComputeConfidence(evaluation, options);
			return true;
		}

		private static bool TryDecodeUtf8(
			byte[] payload,
			SecretDecodeOptions options,
			out string text,
			out double confidence,
			out string? failure)
		{
			text = string.Empty;
			confidence = 0.0;
			failure = null;

			if (payload.Length == 0)
			{
				failure = "Payload empty";
				return false;
			}

			string decoded;
			try
			{
				decoded = Encoding.UTF8.GetString(payload).TrimEnd('\0');
			}
			catch (Exception ex)
			{
				failure = ex.Message;
				return false;
			}

			if (!TryEvaluateText(decoded, options, out var evaluation, out failure))
				return false;

			text = decoded;
			confidence = ComputeConfidence(evaluation, options);
			return true;
		}

		private static bool TryReadFixedUtf16Internal(
			ReadOnlySpan<byte> payload,
			int offset,
			int length,
			out string text,
			out int bytesConsumed)
		{
			text = string.Empty;
			bytesConsumed = 0;

			if (length <= 0)
				return false;
			if (offset < 0 || offset >= payload.Length)
				return false;

			int byteLength = length;
			if (byteLength % 2 != 0)
			{
				int altLength = checked(length * 2);
				if (offset + altLength > payload.Length)
					return false;
				byteLength = altLength;
			}

			if (offset + byteLength > payload.Length)
				return false;

			try
			{
				text = Encoding.Unicode.GetString(payload.Slice(offset, byteLength)).TrimEnd('\0');
			}
			catch
			{
				return false;
			}

			bytesConsumed = byteLength;
			return !string.IsNullOrEmpty(text);
		}

		private static bool TryEvaluateText(string text, SecretDecodeOptions options, out TextEvaluation evaluation, out string? failure)
		{
			evaluation = AnalyzeText(text);
			failure = null;

			if (string.IsNullOrWhiteSpace(text))
			{
				failure = "Text was empty";
				return false;
			}

			if (options.MinTextLength > 0 && text.Length < options.MinTextLength)
			{
				failure = $"Text length {text.Length} below minimum {options.MinTextLength}";
				return false;
			}

			if (options.RejectReplacementChar && text.IndexOf('\uFFFD') >= 0)
			{
				failure = "Text contains replacement characters";
				return false;
			}

			if (!options.AllowControlChars && evaluation.ControlCount > 0)
			{
				failure = "Text contains control characters";
				return false;
			}

			if (options.MinAsciiCount > 0 && evaluation.AsciiPrintableCount < options.MinAsciiCount)
			{
				failure = $"ASCII count {evaluation.AsciiPrintableCount} below minimum {options.MinAsciiCount}";
				return false;
			}

			if (options.MinAsciiRatio > 0 && evaluation.AsciiRatio < options.MinAsciiRatio)
			{
				failure = $"ASCII ratio {evaluation.AsciiRatio:0.00} below {options.MinAsciiRatio:0.00}";
				return false;
			}

			if (options.MinPrintableRatio > 0 && evaluation.PrintableRatio < options.MinPrintableRatio)
			{
				failure = $"Printable ratio {evaluation.PrintableRatio:0.00} below {options.MinPrintableRatio:0.00}";
				return false;
			}

			if (options.MaxNonAsciiRatio < 1.0 && evaluation.NonAsciiRatio > options.MaxNonAsciiRatio)
			{
				failure = $"Non-ASCII ratio {evaluation.NonAsciiRatio:0.00} above {options.MaxNonAsciiRatio:0.00}";
				return false;
			}

			return true;
		}

		private static double ComputeConfidence(TextEvaluation evaluation, SecretDecodeOptions options)
		{
			if (evaluation.Length == 0)
				return 0.0;

			double confidence = (evaluation.AsciiRatio + evaluation.PrintableRatio) / 2.0;
			if (options.MaxNonAsciiRatio < 1.0)
				confidence = Math.Min(confidence, 1.0 - evaluation.NonAsciiRatio);

			return Math.Clamp(confidence, 0.0, 1.0);
		}

		private static bool TryExtractReadableFragments(
			byte[] payload,
			SecretDecodeOptions options,
			out string fragmentText,
			out double confidence)
		{
			fragmentText = string.Empty;
			confidence = 0.0;

			var fragments = new List<(string Fragment, int Offset)>();
			ExtractUnicodeFragments(payload, fragments);
			ExtractAsciiFragments(payload, fragments);

			if (fragments.Count == 0)
				return false;

			var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			var scored = new List<(string Fragment, int Score, int Offset)>();
			foreach (var fragment in fragments)
			{
				var normalized = NormalizeFragment(fragment.Fragment, options.MaxFragmentLength);
				if (string.IsNullOrWhiteSpace(normalized))
					continue;
				if (!IsLikelyFragment(normalized, options.MinFragmentLength))
					continue;
				if (!seen.Add(normalized))
					continue;

				var score = ScoreFragment(normalized);
				scored.Add((normalized, score, fragment.Offset));
			}

			if (scored.Count == 0)
				return false;

			var selected = scored
				.OrderByDescending(item => item.Score)
				.ThenBy(item => item.Offset)
				.Take(options.MaxFragments)
				.Select(item => item.Fragment)
				.ToList();

			if (selected.Count == 0)
				return false;

			fragmentText = string.Join(Environment.NewLine, selected);
			if (!TryEvaluateText(fragmentText, options, out var evaluation, out _))
				return false;

			confidence = ComputeConfidence(evaluation, options);
			return true;
		}

		private static void ExtractUnicodeFragments(byte[] payload, List<(string Fragment, int Offset)> results)
		{
			if (payload.Length < 2)
				return;

			var builder = new StringBuilder();
			var startOffset = -1;

			for (var i = 0; i + 1 < payload.Length; i += 2)
			{
				var ch = (char)(payload[i] | (payload[i + 1] << 8));
				if (IsPrintableTextChar(ch))
				{
					if (startOffset < 0)
						startOffset = i;
					builder.Append(ch);
					continue;
				}

				if (builder.Length > 0)
				{
					results.Add((builder.ToString(), startOffset));
					builder.Clear();
					startOffset = -1;
				}
			}

			if (builder.Length > 0)
				results.Add((builder.ToString(), startOffset));
		}

		private static void ExtractAsciiFragments(byte[] payload, List<(string Fragment, int Offset)> results)
		{
			if (payload.Length == 0)
				return;

			var builder = new StringBuilder();
			var startOffset = -1;

			for (var i = 0; i < payload.Length; i++)
			{
				var value = payload[i];
				if (value >= 0x20 && value <= 0x7E)
				{
					if (startOffset < 0)
						startOffset = i;
					builder.Append((char)value);
					continue;
				}

				if (builder.Length > 0)
				{
					results.Add((builder.ToString(), startOffset));
					builder.Clear();
					startOffset = -1;
				}
			}

			if (builder.Length > 0)
				results.Add((builder.ToString(), startOffset));
		}

		private static bool IsLikelyFragment(string fragment, int minLength)
		{
			if (string.IsNullOrWhiteSpace(fragment))
				return false;

			var trimmed = fragment.Trim();
			if (trimmed.Length < minLength)
				return false;

			var letters = 0;
			var digits = 0;
			foreach (var ch in trimmed)
			{
				if (char.IsLetter(ch))
					letters++;
				else if (char.IsDigit(ch))
					digits++;
			}

			if (letters + digits < Math.Min(3, trimmed.Length))
				return false;

			return true;
		}

		private static string NormalizeFragment(string fragment, int maxLength)
		{
			var trimmed = fragment.Trim();
			if (trimmed.Length > maxLength)
				return trimmed.Substring(0, maxLength) + "...";
			return trimmed;
		}

		private static int ScoreFragment(string fragment)
		{
			var score = fragment.Length;

			if (fragment.IndexOf("target=", StringComparison.OrdinalIgnoreCase) >= 0)
				score += 20;
			if (fragment.Contains("://", StringComparison.Ordinal))
				score += 10;
			if (fragment.Contains('@'))
				score += 6;
			if (fragment.Contains('\\') || fragment.Contains('/'))
				score += 4;
			if (fragment.Contains('='))
				score += 6;
			if (fragment.Contains(':'))
				score += 3;
			if (fragment.IndexOf("authstate", StringComparison.OrdinalIgnoreCase) >= 0)
				score -= 15;

			return score;
		}

		private static bool IsPrintableTextChar(char ch)
		{
			if (ch == '\r' || ch == '\n' || ch == '\t')
				return false;
			return !char.IsControl(ch);
		}

		private static TextEvaluation AnalyzeText(string text)
		{
			int printable = 0;
			int asciiPrintable = 0;
			int nonAsciiPrintable = 0;
			int control = 0;

			foreach (var ch in text)
			{
				if (char.IsControl(ch) && ch != '\r' && ch != '\n' && ch != '\t')
				{
					control++;
					continue;
				}

				printable++;
				if (ch >= ' ' && ch <= '~')
					asciiPrintable++;
				else if (ch > '\u007e')
					nonAsciiPrintable++;
			}

			return new TextEvaluation(text.Length, printable, asciiPrintable, nonAsciiPrintable, control);
		}

		private readonly struct TextEvaluation
		{
			public TextEvaluation(int length, int printableCount, int asciiPrintableCount, int nonAsciiPrintableCount, int controlCount)
			{
				Length = length;
				PrintableCount = printableCount;
				AsciiPrintableCount = asciiPrintableCount;
				NonAsciiPrintableCount = nonAsciiPrintableCount;
				ControlCount = controlCount;
			}

			public int Length { get; }
			public int PrintableCount { get; }
			public int AsciiPrintableCount { get; }
			public int NonAsciiPrintableCount { get; }
			public int ControlCount { get; }

			public double PrintableRatio => Length == 0 ? 0.0 : (double)PrintableCount / Length;
			public double AsciiRatio => Length == 0 ? 0.0 : (double)AsciiPrintableCount / Length;
			public double NonAsciiRatio => Length == 0 ? 0.0 : (double)NonAsciiPrintableCount / Length;
		}
	}
}
