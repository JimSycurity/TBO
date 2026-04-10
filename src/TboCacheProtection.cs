using System;
using System.Security.Cryptography;
using System.Text;

namespace Titanis.Tbo.Smb2.PowerShell
{
	internal static class TboCacheProtection
	{
		internal const string ProtectDpapiEnvVar = "TITANIS_TBO_CACHE_PROTECT_DPAPI";
		private static readonly byte[] ProtectedPrefix = Encoding.ASCII.GetBytes("TBOCACHE:DPAPI:V1:");

		internal static bool IsDpapiProtectionEnabled()
		{
			var env = Environment.GetEnvironmentVariable(ProtectDpapiEnvVar);
			return !string.IsNullOrWhiteSpace(env) && TboCacheDatabase.IsTruthy(env);
		}

		internal static byte[] ProtectDpapiPayloadForStorage(byte[] payload, string contextLabel)
		{
			if (payload == null)
				throw new ArgumentNullException(nameof(payload));

			if (payload.Length == 0)
				return payload;
			if (IsProtectedPayload(payload))
				return payload;
			if (!IsDpapiProtectionEnabled())
				return payload;
			if (!OperatingSystem.IsWindows())
			{
				throw new PlatformNotSupportedException(
					$"DPAPI cache protection is enabled via {ProtectDpapiEnvVar}, but this platform does not support Windows DPAPI protection.");
			}

			try
			{
				var protectedPayload = ProtectedData.Protect(payload, optionalEntropy: null, scope: DataProtectionScope.CurrentUser);
				var wrapped = new byte[ProtectedPrefix.Length + protectedPayload.Length];
				Buffer.BlockCopy(ProtectedPrefix, 0, wrapped, 0, ProtectedPrefix.Length);
				Buffer.BlockCopy(protectedPayload, 0, wrapped, ProtectedPrefix.Length, protectedPayload.Length);
				return wrapped;
			}
			catch (Exception ex)
			{
				throw new InvalidOperationException($"Failed to protect cache payload for {contextLabel}: {ex.Message}", ex);
			}
		}

		internal static bool TryUnprotectDpapiPayloadFromStorage(
			byte[] payload,
			string contextLabel,
			Action<string>? logDiagnostic,
			out byte[] cleartext,
			out string? failureReason)
		{
			logDiagnostic ??= _ => { };
			cleartext = payload ?? Array.Empty<byte>();
			failureReason = null;

			if (payload == null || payload.Length == 0)
				return true;
			if (!IsProtectedPayload(payload))
				return true;
			if (payload.Length <= ProtectedPrefix.Length)
			{
				failureReason = $"Protected cache payload for {contextLabel} is truncated.";
				logDiagnostic($"TBO cache: {failureReason}");
				cleartext = Array.Empty<byte>();
				return false;
			}
			if (!OperatingSystem.IsWindows())
			{
				failureReason = $"Protected cache payload for {contextLabel} requires Windows DPAPI.";
				logDiagnostic($"TBO cache: {failureReason}");
				cleartext = Array.Empty<byte>();
				return false;
			}

			try
			{
				var protectedBytes = payload.AsSpan(ProtectedPrefix.Length).ToArray();
				cleartext = ProtectedData.Unprotect(protectedBytes, optionalEntropy: null, scope: DataProtectionScope.CurrentUser);
				return true;
			}
			catch (Exception ex)
			{
				failureReason = $"Failed to unprotect cache payload for {contextLabel}: {ex.Message}";
				logDiagnostic($"TBO cache: {failureReason}");
				cleartext = Array.Empty<byte>();
				return false;
			}
		}

		internal static bool IsProtectedPayload(ReadOnlySpan<byte> payload)
		{
			return payload.Length >= ProtectedPrefix.Length
				&& payload.Slice(0, ProtectedPrefix.Length).SequenceEqual(ProtectedPrefix);
		}
	}
}
