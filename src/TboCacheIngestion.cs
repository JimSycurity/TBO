using System;
using System.Text;
using System.Text.Json;
using Titanis.Crypto;

namespace Titanis.Tbo.Smb2.PowerShell
{
	/// <summary>
	/// Small, normalized ingestion surface for writing observations into the persistent cache.
	/// </summary>
	/// <remarks>
	/// Callers should not execute SQL directly. Use this helper to upsert entities and insert observations.
	/// </remarks>
	internal static class TboCacheIngestion
	{
		internal sealed class AddObservationArgs
		{
			internal string ServerName { get; init; } = "";
			internal string SourceKind { get; init; } = "";
			internal string? SourcePath { get; init; }
			internal DateTime? ObservedUtc { get; init; }
			internal int? Confidence { get; init; }
			internal string? ContextJson { get; init; }

			internal string? PrincipalSid { get; init; }
			internal string? PrincipalDomain { get; init; }
			internal string? PrincipalName { get; init; }
			internal string? PrincipalType { get; init; }

			internal string? CredentialKind { get; init; }
			internal string? CredentialIdentifier { get; init; }

			internal string? CachePath { get; init; }
		}

		internal sealed class AddObservationResult
		{
			internal string CachePath { get; init; } = "";

			internal long ObservationId { get; init; }
			internal DateTime ObservedUtc { get; init; }
			internal int? Confidence { get; init; }
			internal string? ContextJson { get; init; }

			internal long MachineId { get; init; }
			internal string ServerName { get; init; } = "";

			internal long? PrincipalId { get; init; }
			internal string? PrincipalSid { get; init; }
			internal string? PrincipalDomain { get; init; }
			internal string? PrincipalName { get; init; }
			internal string? PrincipalType { get; init; }

			internal long? CredentialId { get; init; }
			internal string? CredentialKind { get; init; }
			internal string? CredentialIdentifier { get; init; }

			internal string SourceKind { get; init; } = "";
			internal string? SourcePath { get; init; }
		}

		internal static AddObservationResult AddObservation(AddObservationArgs args, Action<string>? logDiagnostic = null)
		{
			if (args == null)
				throw new ArgumentNullException(nameof(args));

			logDiagnostic ??= _ => { };

			var serverName = RequireNonEmpty(args.ServerName, nameof(args.ServerName));
			var sourceKind = RequireNonEmpty(args.SourceKind, nameof(args.SourceKind));
			var sourcePath = NormalizeOptional(args.SourcePath);

			var observedUtc = (args.ObservedUtc ?? DateTime.UtcNow).ToUniversalTime();
			var confidence = args.Confidence;
			var contextJson = NormalizeOptional(args.ContextJson);

			if (confidence.HasValue && (confidence.Value < 0 || confidence.Value > 100))
				throw new ArgumentOutOfRangeException(nameof(args.Confidence), confidence.Value, "Confidence must be between 0 and 100.");

			var principalSid = NormalizeOptional(args.PrincipalSid);
			var principalDomain = NormalizeOptional(args.PrincipalDomain);
			var principalName = NormalizeOptional(args.PrincipalName);
			var principalType = NormalizeOptional(args.PrincipalType);

			var credentialKind = NormalizeOptional(args.CredentialKind);
			var credentialIdentifier = NormalizeOptional(args.CredentialIdentifier);

			// "PrincipalType" is metadata, not identity. Avoid creating a principal record without some identifier.
			var hasPrincipal = !string.IsNullOrWhiteSpace(principalSid)
				|| !string.IsNullOrWhiteSpace(principalName);

			var hasCredential = !string.IsNullOrWhiteSpace(credentialKind)
				|| !string.IsNullOrWhiteSpace(credentialIdentifier);

			if (!hasPrincipal && !hasCredential)
				throw new ArgumentException("At least one principal or credential identity field must be provided.", nameof(args));

			if (hasCredential)
			{
				if (string.IsNullOrWhiteSpace(credentialKind) || string.IsNullOrWhiteSpace(credentialIdentifier))
					throw new ArgumentException("CredentialKind and CredentialIdentifier must be provided together.", nameof(args));

				credentialKind = credentialKind.Trim();
				credentialIdentifier = NormalizeCredentialIdentifier(credentialIdentifier);
			}

			using var db = TboCacheDatabase.Open(args.CachePath, logDiagnostic);

			var machineId = db.UpsertMachine(serverName);

			long? principalId = null;
			if (hasPrincipal)
				principalId = db.UpsertPrincipal(principalSid, principalDomain, principalName, principalType);

			long? credentialId = null;
			if (hasCredential)
				credentialId = db.UpsertCredential(credentialKind!, credentialIdentifier!);

			var observationId = db.InsertObservation(
				machineId: machineId,
				principalId: principalId,
				credentialId: credentialId,
				sourceKind: sourceKind,
				sourcePath: sourcePath,
				observedUtc: observedUtc,
				contextJson: contextJson,
				confidence: confidence);

			// Offline enrichment for cached plaintext credentials:
			// derive/store NTHash and link it to the same machine/principal/source graph edge.
			MaybeIngestDerivedNtHash(
				db,
				serverName,
				machineId,
				principalId,
				principalSid,
				principalName,
				credentialKind,
				credentialIdentifier,
				sourceKind,
				sourcePath,
				observedUtc,
				confidence,
				contextJson,
				observationId,
				logDiagnostic);

			return new AddObservationResult
			{
				CachePath = TboCacheDatabase.ResolveCachePath(args.CachePath),

				ObservationId = observationId,
				ObservedUtc = observedUtc,
				Confidence = confidence,
				ContextJson = contextJson,

				MachineId = machineId,
				ServerName = serverName,

				PrincipalId = principalId,
				PrincipalSid = principalSid,
				PrincipalDomain = principalDomain,
				PrincipalName = principalName,
				PrincipalType = principalType,

				CredentialId = credentialId,
				CredentialKind = credentialKind,
				CredentialIdentifier = credentialIdentifier,

				SourceKind = sourceKind,
				SourcePath = sourcePath,
			};
		}

		private static void MaybeIngestDerivedNtHash(
			TboCacheDatabase db,
			string serverName,
			long machineId,
			long? principalId,
			string? principalSid,
			string? principalName,
			string? credentialKind,
			string? credentialIdentifier,
			string sourceKind,
			string? sourcePath,
			DateTime observedUtc,
			int? confidence,
			string? contextJson,
			long sourceObservationId,
			Action<string> logDiagnostic)
		{
			if (!string.Equals(credentialKind, "Password", StringComparison.OrdinalIgnoreCase))
				return;

			if (credentialIdentifier == null)
				return;

			if (!TryDeriveNtHashHex(credentialIdentifier, out var ntHashHex))
				return;

			try
			{
				var derivedCredentialId = db.UpsertCredential("NTHash", ntHashHex);
				var derivedContext = BuildDerivedNtHashContextJson(contextJson, sourceObservationId);
				db.InsertObservation(
					machineId: machineId,
					principalId: principalId,
					credentialId: derivedCredentialId,
					sourceKind: sourceKind,
					sourcePath: sourcePath,
					observedUtc: observedUtc,
					contextJson: derivedContext,
					confidence: confidence);

				if (!string.IsNullOrWhiteSpace(principalSid))
				{
					db.UpsertVerifiedPasswordHash(
						machineId: machineId,
						serverName: serverName,
						userSid: principalSid,
						userName: principalName,
						hashType: DpapiVerifiedHashTypes.NtPwd,
						hashValueHex: ntHashHex,
						verifiedByCmdlet: sourceKind,
						verifiedVia: "cache_password_derived");
				}
			}
			catch (Exception ex)
			{
				logDiagnostic($"TBO cache: failed to derive NTHash from Password observation on {serverName}: {ex.Message}");
			}
		}

		private static bool TryDeriveNtHashHex(string password, out string ntHashHex)
		{
			ntHashHex = string.Empty;

			var passwordUtf16 = Encoding.Unicode.GetBytes(password);
			var ntHash = SlimHashAlgorithm.ComputeHash<Md4Context>(passwordUtf16);
			if (ntHash == null || ntHash.Length == 0)
				return false;

			ntHashHex = Convert.ToHexString(ntHash).ToLowerInvariant();
			return true;
		}

		private static string BuildDerivedNtHashContextJson(string? originalContextJson, long sourceObservationId)
		{
			var payload = new
			{
				derived = "NTHash",
				derivedFromKind = "Password",
				sourceObservationId,
				sourceContextJson = originalContextJson
			};
			return JsonSerializer.Serialize(payload);
		}

		private static string RequireNonEmpty(string? value, string paramName)
		{
			if (string.IsNullOrWhiteSpace(value))
				throw new ArgumentException("Value must be provided.", paramName);

			return value.Trim();
		}

		private static string? NormalizeOptional(string? value)
			=> string.IsNullOrWhiteSpace(value) ? null : value.Trim();

		private static string NormalizeCredentialIdentifier(string identifier)
		{
			var trimmed = identifier.Trim();
			if (LooksLikeHex(trimmed))
				return trimmed.ToLowerInvariant();

			return trimmed;
		}

		private static bool LooksLikeHex(string value)
		{
			if (string.IsNullOrWhiteSpace(value))
				return false;

			foreach (var ch in value)
			{
				if (!Uri.IsHexDigit(ch))
					return false;
			}

			return true;
		}
	}
}
