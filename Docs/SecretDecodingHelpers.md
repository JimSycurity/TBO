# Shared Secret Decoding Helpers

## Scope
Design a shared, public helper API for decoding secret payloads and presenting them consistently across LSA, SAM, DPAPI, CredMan, and CredVault. This design focuses on shared text/hex decoding and diagnostics, while keeping domain-specific parsing in the feature-specific cmdlets.

## Current Hotspots
Area | Files | Notes
LSA secrets | `src/TboRegLsaSecretCmdlet.cs`, `src/GetRegLsaSecrets.cs`, `src/GetRegMachineAccount.cs` | UTF-16/UTF-8 decode heuristics, payload length extraction, DPAPI_SYSTEM splitting, hex fallback.
DPAPI blobs | `src/DpapiHelpers.cs`, `src/GetDpapiBlob.cs`, `src/DpapiBlobCrypto.cs` | UTF-16/UTF-8 decode heuristics and hex output for cleartext bytes.
CredMan / CredVault | `src/GetCredMan.cs` | Structured parsing for credential and vault formats; multiple string decode helpers and fragment extraction fallback.
SAM | `src/GetRegSamHashes.cs` | Hash extraction and hex formatting; no text decoding.
Registry string helpers | `src/RegistryHelpers.cs` | UTF-16 decoding and multi-string handling; used by multiple cmdlets.

## Common Patterns Worth Sharing
- UTF-16LE and UTF-8 decoding with heuristics (trim nulls, reject low printable ratio).
- Length-prefixed UTF-16 strings and fixed-length UTF-16 strings.
- Hex fallback for binary blobs that do not decode to text.
- Fragment extraction for partially readable payloads (currently in CredMan).
- Common diagnostic messages when decode attempts fail.

## Proposed Public Helper API
Public helpers should live in `src/SecretDecodingHelpers.cs` (namespace `Titanis.Tbo.Smb2.PowerShell`).

Suggested types:
- `public sealed record SecretDecodeResult` with `Text`, `Hex`, `Encoding`, `Confidence`, `FailureReason`, and `BytesLength`.
- `public sealed record SecretDecodeOptions` with:
  - Text heuristics: `MinTextLength`, `MinAsciiCount`, `MinAsciiRatio`, `MinPrintableRatio`, `MaxNonAsciiRatio`
  - Safety toggles: `RejectReplacementChar`, `AllowControlChars`
  - Fallbacks: `AllowFragmentFallback`, `IncludeHexOnFailure`
  - Fragment tuning: `MinFragmentLength`, `MaxFragmentLength`, `MaxFragments`
- `public static class SecretDecoding` with:
  - `SecretDecodeResult TryDecode(byte[] payload, SecretDecodeOptions? options = null, Action<string>? log = null)`
  - `bool TryDecodeUtf16(byte[] payload, out string text)`
  - `bool TryDecodeUtf8(byte[] payload, out string text)`
  - `bool TryReadLengthPrefixedUtf16(ReadOnlySpan<byte> payload, ref int offset, out string text)`
  - `bool TryReadFixedUtf16(ReadOnlySpan<byte> payload, int length, out string text)`
  - `string? TryExtractReadableFragments(byte[] payload, SecretDecodeOptions? options = null)`
  - `string? ToHexIfBinary(byte[] payload)`

Notes:
- `TryDecode` should keep behavior compatible with existing heuristics in `TboRegLsaSecretCmdlet` and `DpapiHelpers`.
- Fragment extraction should be optional and primarily used by CredMan fallback paths.
- Result should report encoding used (e.g., `UTF-16LE`, `UTF-8`, `HEX`, `FRAGMENTS`).

## Diagnostics
Add optional logging hooks to surface why decode failed without changing output:
- Example messages: `"DecodeUtf16 rejected (printable ratio < threshold)"`, `"DecodeUtf8 rejected (non-ASCII ratio high)"`, `"Fragment extraction produced N candidates"`.
- Logging should be `verbose`-level only to avoid noisy defaults.

## Boundaries and Non-Goals
- CredMan/CredVault structured parsing stays in `GetCredMan.cs`; helpers only cover text decoding and fragment extraction used in fallback paths.
- DPAPI blob parsing and crypto stays in `DpapiBlobCrypto`.
- SAM hash parsing stays specialized; only shared hex formatting is applicable.
- Registry string decoding for non-secret values can optionally migrate later, but is out of scope for the initial helper.

## Migration Plan
- Introduce helper types and utilities first.
- Migrate LSA secret decoding to helpers (maintain DPAPI_SYSTEM and hex-specific behavior).
- Migrate DPAPI cleartext decoding to helpers.
- Update CredMan/CredVault fallback decoding to use shared helpers where safe.
- Optionally migrate general registry string decoding later.

## Proposed Child Issues
- Add shared `SecretDecoding` helpers and result types (no behavioral change).
- Migrate LSA secret decoding (`TboRegLsaSecretCmdlet`) to shared helpers.
- Migrate DPAPI cleartext decoding (`DpapiHelpers`, `GetDpapiBlob`) to shared helpers.
- Migrate CredMan/CredVault fallback decoding to shared helpers (keep structured parsing intact).
- Optional: consolidate registry string helpers to shared decode utilities.

## Decisions
- `SecretDecodeResult` should expose a numeric confidence score alongside the encoding label.
- Fragment extraction should be disabled by default and only enabled for CredMan/CredVault fallback paths.
