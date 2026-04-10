using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Text;
using System.Text.Json;

namespace Titanis.Tbo.Smb2.PowerShell
{
	public sealed class TboCacheInfo
	{
		public string? Path { get; init; }
		public int SchemaVersion { get; init; }

		public long MachineCount { get; init; }
		public long PrincipalCount { get; init; }
		public long CredentialCount { get; init; }
		public long ObservationCount { get; init; }

		public long DpapiMasterKeyCount { get; init; }
		public long DpapiBlobCount { get; init; }

		public long WriteActivityCount { get; init; }
	}

	public sealed class TboCacheCredentialReuse
	{
		public long CredentialId { get; init; }
		public string CredentialKind { get; init; } = "";
		public string CredentialIdentifier { get; init; } = "";
		public long MachineCount { get; init; }

		public string ServerName { get; init; } = "";
		public string? PrincipalSid { get; init; }
		public string? PrincipalDomain { get; init; }
		public string? PrincipalName { get; init; }
		public string? PrincipalType { get; init; }

		public long ObservationCount { get; init; }
		public DateTime FirstObservedUtc { get; init; }
		public DateTime LastObservedUtc { get; init; }
	}

	public sealed class TboCacheCredentialReuseHeatmap
	{
		public long CredentialId { get; init; }
		public string CredentialKind { get; init; } = "";
		public string CredentialIdentifier { get; init; } = "";
		public long MachineCount { get; init; }

		public string ServerName { get; init; } = "";
		public long PrincipalCount { get; init; }
		public long ObservationCount { get; init; }
		public DateTime FirstObservedUtc { get; init; }
		public DateTime LastObservedUtc { get; init; }

		public string[] PrivilegeHints { get; init; } = Array.Empty<string>();
	}

	public sealed class TboCacheCredentialBlastRadius
	{
		public long CredentialId { get; init; }
		public string CredentialKind { get; init; } = "";
		public string CredentialIdentifier { get; init; } = "";
		public long MachineCount { get; init; }
		public long PrincipalCount { get; init; }
		public long ObservationCount { get; init; }

		public DateTime FirstObservedUtc { get; init; }
		public DateTime LastObservedUtc { get; init; }

		public double RecencyDays { get; init; }
		public int RecencyScore { get; init; }
		public int PrivilegeScore { get; init; }
		public int BlastRadiusScore { get; init; }
		public string Priority { get; init; } = "";

		public string[] ServerNames { get; init; } = Array.Empty<string>();
		public string[] PrivilegeHints { get; init; } = Array.Empty<string>();
	}

	public sealed class TboCacheDpapiBacklogItem
	{
		public string CachePath { get; init; } = "";
		public string BacklogKey { get; init; } = "";
		public string ArtifactType { get; init; } = "";
		public long ArtifactId { get; init; }

		public long MachineId { get; init; }
		public string ServerName { get; init; } = "";

		public string? Scope { get; init; }
		public string? UserSid { get; init; }
		public string? MasterKeyGuid { get; init; }

		public string Source { get; init; } = "";
		public string Path { get; init; } = "";
		public string? ValueName { get; init; }

		public bool HasMasterKeyGuid { get; init; }
		public bool HasMasterKeyRecord { get; init; }
		public bool HasCleartextMasterKey { get; init; }
		public long DependentBlobCount { get; init; }

		public string FailureReason { get; init; } = "";
		public DateTime FirstSeenUtc { get; init; }
		public DateTime LastSeenUtc { get; init; }
		public double RecencyDays { get; init; }

		public int PriorityScore { get; set; }
		public string Priority { get; set; } = "";

		public int CandidateCount { get; set; }
	}

	public sealed class TboCacheDpapiCandidateRanking
	{
		public string CachePath { get; init; } = "";
		public string BacklogKey { get; init; } = "";
		public string ArtifactType { get; init; } = "";
		public long ArtifactId { get; init; }

		public long MachineId { get; init; }
		public string ServerName { get; init; } = "";
		public string? UserSid { get; init; }
		public string? MasterKeyGuid { get; init; }

		public int CandidateRank { get; init; }
		public int CandidateScore { get; init; }
		public string CandidatePriority { get; init; } = "";
		public string CandidateSourceClass { get; init; } = "";
		public string CandidateType { get; init; } = "";
		public string CandidateValue { get; init; } = "";
		public string? CandidateUserSid { get; init; }
		public string? CandidateUserName { get; init; }
		public string CandidateSourceKind { get; init; } = "";
		public DateTime CandidateObservedUtc { get; init; }
		public string CandidateReason { get; init; } = "";
	}

	public sealed class TboCacheFinding
	{
		public string CachePath { get; init; } = "";

		public long ObservationId { get; init; }
		public DateTime ObservedUtc { get; init; }
		public int? Confidence { get; init; }
		public string? ContextJson { get; init; }

		public long MachineId { get; init; }
		public string ServerName { get; init; } = "";

		public long? PrincipalId { get; init; }
		public string? PrincipalScope { get; init; }
		public long? PrincipalScopeMachineId { get; init; }
		public string? PrincipalSid { get; init; }
		public string? PrincipalDomain { get; init; }
		public string? PrincipalName { get; init; }
		public string? PrincipalType { get; init; }

		public long? CredentialId { get; init; }
		public string? CredentialKind { get; init; }
		public string? CredentialIdentifier { get; init; }

		public string SourceKind { get; init; } = "";
		public string? SourcePath { get; init; }
	}

	public enum TboCacheEntryType
	{
		Machine = 1,
		Principal = 2,
		Credential = 3,
		Observation = 4
	}

	public enum TboCacheGraphFormat
	{
		Json = 1,
		Dot = 2,
		OpenGraph = 3
	}

	public enum TboCacheCredentialReuseView
	{
		Detail = 1,
		Heatmap = 2,
		BlastRadius = 3
	}

	public enum TboCacheDpapiBacklogView
	{
		Backlog = 1,
		CandidateRanking = 2
	}

	internal static class TboCacheFindingFilters
	{
		internal static IReadOnlyList<WildcardPattern> BuildPatterns(string[]? filters)
		{
			if (filters == null || filters.Length == 0)
				return Array.Empty<WildcardPattern>();

			var patterns = new List<WildcardPattern>();
			foreach (var filter in filters)
			{
				if (string.IsNullOrWhiteSpace(filter))
					continue;

				patterns.Add(new WildcardPattern(filter.Trim(), WildcardOptions.IgnoreCase));
			}

			return patterns;
		}

		internal static bool MatchesAny(string? value, IReadOnlyList<WildcardPattern> patterns)
		{
			if (patterns == null || patterns.Count == 0)
				return true;

			value ??= string.Empty;
			foreach (var pattern in patterns)
			{
				if (pattern.IsMatch(value))
					return true;
			}

			return false;
		}

		internal static string? GetSingleExactFilter(string[]? filters)
		{
			if (filters == null || filters.Length != 1)
				return null;

			var filter = filters[0];
			if (string.IsNullOrWhiteSpace(filter))
				return null;

			filter = filter.Trim();
			if (WildcardPattern.ContainsWildcardCharacters(filter))
				return null;

			return filter;
		}

		internal static TboCacheFinding ToFinding(string resolvedPath, TboCacheDatabase.ObservationFindingRow row)
		{
			return new TboCacheFinding
			{
				CachePath = resolvedPath,
				ObservationId = row.ObservationId,
				ObservedUtc = ParseDateTime(row.ObservedUtc),
				Confidence = row.Confidence,
				ContextJson = row.ContextJson,
				MachineId = row.MachineId,
				ServerName = row.ServerName,
				PrincipalId = row.PrincipalId,
				PrincipalScope = row.PrincipalScope,
				PrincipalScopeMachineId = row.PrincipalScopeMachineId,
				PrincipalSid = row.PrincipalSid,
				PrincipalDomain = row.PrincipalDomain,
				PrincipalName = row.PrincipalName,
				PrincipalType = row.PrincipalType,
				CredentialId = row.CredentialId,
				CredentialKind = row.CredentialKind,
				CredentialIdentifier = row.CredentialIdentifier,
				SourceKind = row.SourceKind,
				SourcePath = row.SourcePath,
			};
		}

		internal static DateTime ParseDateTime(string value)
		{
			if (string.IsNullOrWhiteSpace(value))
				return default;

			if (DateTime.TryParseExact(
				value,
				"O",
				CultureInfo.InvariantCulture,
				DateTimeStyles.RoundtripKind,
				out var parsed))
			{
				return parsed;
			}

			return DateTime.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
		}
	}

	internal static class TboCacheCredentialReuseAnalysis
	{
		private sealed class HeatmapAccumulator
		{
			internal long CredentialId { get; init; }
			internal string CredentialKind { get; init; } = "";
			internal string CredentialIdentifier { get; init; } = "";
			internal long MachineCount { get; init; }
			internal string ServerName { get; init; } = "";
			internal long ObservationCount { get; set; }
			internal DateTime FirstObservedUtc { get; set; } = DateTime.MaxValue;
			internal DateTime LastObservedUtc { get; set; } = DateTime.MinValue;
			internal HashSet<string> PrincipalKeys { get; } = new(StringComparer.OrdinalIgnoreCase);
			internal HashSet<string> PrivilegeHints { get; } = new(StringComparer.OrdinalIgnoreCase);
		}

		private sealed class BlastAccumulator
		{
			internal long CredentialId { get; init; }
			internal string CredentialKind { get; init; } = "";
			internal string CredentialIdentifier { get; init; } = "";
			internal long MachineCount { get; init; }
			internal long ObservationCount { get; set; }
			internal DateTime FirstObservedUtc { get; set; } = DateTime.MaxValue;
			internal DateTime LastObservedUtc { get; set; } = DateTime.MinValue;
			internal HashSet<string> PrincipalKeys { get; } = new(StringComparer.OrdinalIgnoreCase);
			internal HashSet<string> ServerNames { get; } = new(StringComparer.OrdinalIgnoreCase);
			internal HashSet<string> PrivilegeHints { get; } = new(StringComparer.OrdinalIgnoreCase);
		}

		private static readonly IReadOnlyDictionary<string, int> PrivilegeHintWeights =
			new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
			{
				["SYSTEM"] = 45,
				["Domain Admins"] = 50,
				["RID-500"] = 35,
				["Administrator"] = 25,
				["Admin-like name"] = 20,
				["Service account"] = 10,
				["Service principal"] = 10,
			};

		internal static IReadOnlyList<TboCacheCredentialReuseHeatmap> BuildHeatmap(
			IReadOnlyList<TboCacheDatabase.CredentialReuseRow> rows)
		{
			var map = new Dictionary<string, HeatmapAccumulator>(StringComparer.OrdinalIgnoreCase);
			foreach (var row in rows)
			{
				var key = $"{row.CredentialId}|{row.ServerName}";
				if (!map.TryGetValue(key, out var acc))
				{
					acc = new HeatmapAccumulator
					{
						CredentialId = row.CredentialId,
						CredentialKind = row.Kind,
						CredentialIdentifier = row.Identifier,
						MachineCount = row.MachineCount,
						ServerName = row.ServerName,
					};
					map[key] = acc;
				}

				acc.ObservationCount += row.ObservationCount;

				var firstObserved = TboCacheFindingFilters.ParseDateTime(row.FirstObservedUtc);
				var lastObserved = TboCacheFindingFilters.ParseDateTime(row.LastObservedUtc);
				if (firstObserved < acc.FirstObservedUtc)
					acc.FirstObservedUtc = firstObserved;
				if (lastObserved > acc.LastObservedUtc)
					acc.LastObservedUtc = lastObserved;

				AddPrincipalAndHints(acc.PrincipalKeys, acc.PrivilegeHints, row);
			}

			return map.Values
				.Select(acc => new TboCacheCredentialReuseHeatmap
				{
					CredentialId = acc.CredentialId,
					CredentialKind = acc.CredentialKind,
					CredentialIdentifier = acc.CredentialIdentifier,
					MachineCount = acc.MachineCount,
					ServerName = acc.ServerName,
					PrincipalCount = acc.PrincipalKeys.Count,
					ObservationCount = acc.ObservationCount,
					FirstObservedUtc = NormalizeDateTime(acc.FirstObservedUtc),
					LastObservedUtc = NormalizeDateTime(acc.LastObservedUtc),
					PrivilegeHints = acc.PrivilegeHints.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray(),
				})
				.OrderByDescending(x => x.MachineCount)
				.ThenBy(x => x.CredentialKind, StringComparer.OrdinalIgnoreCase)
				.ThenBy(x => x.CredentialIdentifier, StringComparer.OrdinalIgnoreCase)
				.ThenBy(x => x.ServerName, StringComparer.OrdinalIgnoreCase)
				.ToArray();
		}

		internal static IReadOnlyList<TboCacheCredentialBlastRadius> BuildBlastRadius(
			IReadOnlyList<TboCacheDatabase.CredentialReuseRow> rows,
			DateTime asOfUtc)
		{
			var map = new Dictionary<long, BlastAccumulator>();
			foreach (var row in rows)
			{
				if (!map.TryGetValue(row.CredentialId, out var acc))
				{
					acc = new BlastAccumulator
					{
						CredentialId = row.CredentialId,
						CredentialKind = row.Kind,
						CredentialIdentifier = row.Identifier,
						MachineCount = row.MachineCount,
					};
					map[row.CredentialId] = acc;
				}

				acc.ObservationCount += row.ObservationCount;
				acc.ServerNames.Add(row.ServerName);

				var firstObserved = TboCacheFindingFilters.ParseDateTime(row.FirstObservedUtc);
				var lastObserved = TboCacheFindingFilters.ParseDateTime(row.LastObservedUtc);
				if (firstObserved < acc.FirstObservedUtc)
					acc.FirstObservedUtc = firstObserved;
				if (lastObserved > acc.LastObservedUtc)
					acc.LastObservedUtc = lastObserved;

				AddPrincipalAndHints(acc.PrincipalKeys, acc.PrivilegeHints, row);
			}

			asOfUtc = asOfUtc.ToUniversalTime();

			return map.Values
				.Select(acc =>
				{
					var first = NormalizeDateTime(acc.FirstObservedUtc);
					var last = NormalizeDateTime(acc.LastObservedUtc);
					var recencyDays = Math.Max(0, (asOfUtc - last.ToUniversalTime()).TotalDays);
					var recencyScore = ComputeRecencyScore(recencyDays);
					var privilegeScore = ComputePrivilegeScore(acc.PrivilegeHints);
					var blastRadiusScore = ComputeBlastRadiusScore(
						machineCount: acc.MachineCount,
						principalCount: acc.PrincipalKeys.Count,
						recencyScore: recencyScore,
						privilegeScore: privilegeScore);

					return new TboCacheCredentialBlastRadius
					{
						CredentialId = acc.CredentialId,
						CredentialKind = acc.CredentialKind,
						CredentialIdentifier = acc.CredentialIdentifier,
						MachineCount = acc.MachineCount,
						PrincipalCount = acc.PrincipalKeys.Count,
						ObservationCount = acc.ObservationCount,
						FirstObservedUtc = first,
						LastObservedUtc = last,
						RecencyDays = Math.Round(recencyDays, 2, MidpointRounding.AwayFromZero),
						RecencyScore = recencyScore,
						PrivilegeScore = privilegeScore,
						BlastRadiusScore = blastRadiusScore,
						Priority = ScoreToPriority(blastRadiusScore),
						ServerNames = acc.ServerNames.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray(),
						PrivilegeHints = acc.PrivilegeHints.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray(),
					};
				})
				.OrderByDescending(x => x.BlastRadiusScore)
				.ThenByDescending(x => x.MachineCount)
				.ThenByDescending(x => x.PrincipalCount)
				.ThenByDescending(x => x.LastObservedUtc)
				.ThenBy(x => x.CredentialKind, StringComparer.OrdinalIgnoreCase)
				.ThenBy(x => x.CredentialIdentifier, StringComparer.OrdinalIgnoreCase)
				.ToArray();
		}

		private static DateTime NormalizeDateTime(DateTime value)
		{
			if (value == DateTime.MinValue || value == DateTime.MaxValue)
				return default;
			return value;
		}

		private static void AddPrincipalAndHints(
			HashSet<string> principalKeys,
			HashSet<string> privilegeHints,
			TboCacheDatabase.CredentialReuseRow row)
		{
			var principalKey = BuildPrincipalKey(row);
			if (!string.IsNullOrWhiteSpace(principalKey))
				principalKeys.Add(principalKey);

			foreach (var hint in DerivePrivilegeHints(row))
				privilegeHints.Add(hint);
		}

		private static string? BuildPrincipalKey(TboCacheDatabase.CredentialReuseRow row)
		{
			if (!string.IsNullOrWhiteSpace(row.PrincipalSid))
				return $"sid:{row.PrincipalSid}";

			if (string.IsNullOrWhiteSpace(row.PrincipalDomain)
				&& string.IsNullOrWhiteSpace(row.PrincipalName)
				&& string.IsNullOrWhiteSpace(row.PrincipalType))
			{
				return null;
			}

			return $"{row.PrincipalDomain}|{row.PrincipalName}|{row.PrincipalType}";
		}

		private static IEnumerable<string> DerivePrivilegeHints(TboCacheDatabase.CredentialReuseRow row)
		{
			var sid = row.PrincipalSid?.Trim();
			var name = row.PrincipalName?.Trim();
			var type = row.PrincipalType?.Trim();

			if (string.Equals(sid, "S-1-5-18", StringComparison.OrdinalIgnoreCase))
				yield return "SYSTEM";
			if (!string.IsNullOrWhiteSpace(sid) && sid.EndsWith("-500", StringComparison.OrdinalIgnoreCase))
				yield return "RID-500";
			if (!string.IsNullOrWhiteSpace(sid) && sid.EndsWith("-512", StringComparison.OrdinalIgnoreCase))
				yield return "Domain Admins";

			if (string.Equals(name, "Administrator", StringComparison.OrdinalIgnoreCase))
				yield return "Administrator";
			if (!string.IsNullOrWhiteSpace(name) && name.Contains("admin", StringComparison.OrdinalIgnoreCase))
				yield return "Admin-like name";
			if (!string.IsNullOrWhiteSpace(name)
				&& (name.StartsWith("svc_", StringComparison.OrdinalIgnoreCase)
					|| name.StartsWith("svc-", StringComparison.OrdinalIgnoreCase)
					|| name.StartsWith("svc", StringComparison.OrdinalIgnoreCase)))
			{
				yield return "Service account";
			}

			if (!string.IsNullOrWhiteSpace(type) && type.Contains("service", StringComparison.OrdinalIgnoreCase))
				yield return "Service principal";
		}

		private static int ComputeRecencyScore(double recencyDays)
		{
			if (recencyDays <= 1)
				return 100;
			if (recencyDays <= 7)
				return 90;
			if (recencyDays <= 30)
				return 70;
			if (recencyDays <= 90)
				return 45;
			if (recencyDays <= 180)
				return 25;
			return 10;
		}

		private static int ComputePrivilegeScore(IEnumerable<string> hints)
		{
			var score = 0;
			foreach (var hint in hints)
			{
				if (PrivilegeHintWeights.TryGetValue(hint, out var weight))
					score += weight;
			}

			return Math.Min(100, score);
		}

		private static int ComputeBlastRadiusScore(
			long machineCount,
			int principalCount,
			int recencyScore,
			int privilegeScore)
		{
			var machineScore = Math.Min(100, (int)(machineCount * 20));
			var principalScore = Math.Min(100, principalCount * 12);

			var blended =
				(machineScore * 0.45) +
				(principalScore * 0.20) +
				(recencyScore * 0.20) +
				(privilegeScore * 0.15);

			return (int)Math.Round(blended, MidpointRounding.AwayFromZero);
		}

		private static string ScoreToPriority(int score)
		{
			if (score >= 80)
				return "Critical";
			if (score >= 60)
				return "High";
			if (score >= 40)
				return "Medium";
			if (score >= 20)
				return "Low";
			return "Informational";
		}
	}

	internal static class TboCacheDpapiBacklogAnalysis
	{
		private readonly record struct MachineGuidKey(long MachineId, string MasterKeyGuid);

		internal sealed class BacklogBuildResult
		{
			internal TboCacheDpapiBacklogItem BacklogItem { get; init; } = new();
			internal IReadOnlyList<TboCacheDpapiCandidateRanking> Candidates { get; init; } = Array.Empty<TboCacheDpapiCandidateRanking>();
		}

		private sealed class CandidateAggregate
		{
			internal string SourceClass { get; init; } = "";
			internal string CandidateType { get; init; } = "";
			internal string CandidateValue { get; init; } = "";
			internal string? UserSid { get; init; }
			internal string? UserName { get; init; }
			internal string SourceKind { get; set; } = "";
			internal DateTime LastObservedUtc { get; set; }
		}

		internal static IReadOnlyList<BacklogBuildResult> Build(
			TboCacheDatabase db,
			string resolvedPath,
			DateTime asOfUtc,
			bool includeResolved)
		{
			var graph = db.QueryGraphData();
			var masterKeys = db.QueryDpapiMasterKeys();
			var blobs = db.QueryDpapiBlobs();
			var asOf = asOfUtc.ToUniversalTime();

			var serverByMachineId = graph.Machines.ToDictionary(x => x.MachineId, x => x.ServerName, EqualityComparer<long>.Default);
			var cleartextMasterKeys = new HashSet<MachineGuidKey>();
			var hasMasterKeyRecord = new HashSet<MachineGuidKey>();
			var sidByMasterKey = new Dictionary<MachineGuidKey, string>(new MachineGuidKeyComparer());
			var scopeByMasterKey = new Dictionary<MachineGuidKey, string>(new MachineGuidKeyComparer());
			var dependentBlobCount = new Dictionary<MachineGuidKey, long>(new MachineGuidKeyComparer());

			foreach (var blob in blobs)
			{
				if (string.IsNullOrWhiteSpace(blob.MasterKeyGuid))
					continue;

				var key = new MachineGuidKey(blob.MachineId, blob.MasterKeyGuid.Trim().ToLowerInvariant());
				if (dependentBlobCount.TryGetValue(key, out var count))
					dependentBlobCount[key] = count + 1;
				else
					dependentBlobCount[key] = 1;
			}

			foreach (var mk in masterKeys)
			{
				if (string.IsNullOrWhiteSpace(mk.MasterKeyGuid))
					continue;

				var key = new MachineGuidKey(mk.MachineId, mk.MasterKeyGuid.Trim().ToLowerInvariant());
				hasMasterKeyRecord.Add(key);

				if (!string.IsNullOrWhiteSpace(mk.UserSid) && !sidByMasterKey.ContainsKey(key))
					sidByMasterKey[key] = mk.UserSid!;
				if (!string.IsNullOrWhiteSpace(mk.Scope) && !scopeByMasterKey.ContainsKey(key))
					scopeByMasterKey[key] = mk.Scope;

				if (mk.CleartextKey != null && mk.CleartextKey.Length > 0)
					cleartextMasterKeys.Add(key);
			}

			var candidatesByServer = BuildCandidateMapByServer(db, graph, serverByMachineId);
			var results = new List<BacklogBuildResult>();

			foreach (var mk in masterKeys)
			{
				if (!serverByMachineId.TryGetValue(mk.MachineId, out var serverName))
					continue;

				var normalizedGuid = (mk.MasterKeyGuid ?? string.Empty).Trim().ToLowerInvariant();
				var key = new MachineGuidKey(mk.MachineId, normalizedGuid);
				var hasCleartext = cleartextMasterKeys.Contains(key);
				var blobCount = dependentBlobCount.TryGetValue(key, out var depCount) ? depCount : 0;
				var unresolved = !hasCleartext;

				if (!includeResolved && !unresolved)
					continue;

				var firstSeen = TboCacheFindingFilters.ParseDateTime(mk.FirstSeenUtc);
				var lastSeen = TboCacheFindingFilters.ParseDateTime(mk.LastSeenUtc);
				var recencyDays = Math.Max(0, (asOf - lastSeen.ToUniversalTime()).TotalDays);
				var failureReason = string.IsNullOrWhiteSpace(mk.FailureReason)
					? (hasCleartext ? "Resolved: cleartext key present in cache." : "Master key cleartext not present in cache.")
					: mk.FailureReason!;

				var item = new TboCacheDpapiBacklogItem
				{
					CachePath = resolvedPath,
					BacklogKey = $"MK:{mk.DpapiMasterKeyId}",
					ArtifactType = "MasterKey",
					ArtifactId = mk.DpapiMasterKeyId,
					MachineId = mk.MachineId,
					ServerName = serverName,
					Scope = mk.Scope,
					UserSid = mk.UserSid,
					MasterKeyGuid = mk.MasterKeyGuid,
					Source = "dpapi_masterkeys",
					Path = mk.KeyPath,
					HasMasterKeyGuid = !string.IsNullOrWhiteSpace(mk.MasterKeyGuid),
					HasMasterKeyRecord = hasMasterKeyRecord.Contains(key),
					HasCleartextMasterKey = hasCleartext,
					DependentBlobCount = blobCount,
					FailureReason = failureReason,
					FirstSeenUtc = firstSeen,
					LastSeenUtc = lastSeen,
					RecencyDays = Math.Round(recencyDays, 2, MidpointRounding.AwayFromZero),
				};

				var rankedCandidates = BuildRankedCandidates(item, candidatesByServer, asOf);
				item.CandidateCount = rankedCandidates.Count;
				item.PriorityScore = ComputeBacklogScore(item, unresolved);
				item.Priority = ScoreToPriority(item.PriorityScore);

				results.Add(new BacklogBuildResult
				{
					BacklogItem = item,
					Candidates = rankedCandidates
				});
			}

			foreach (var blob in blobs)
			{
				if (!serverByMachineId.TryGetValue(blob.MachineId, out var serverName))
					continue;

				var hasMasterGuid = !string.IsNullOrWhiteSpace(blob.MasterKeyGuid);
				var normalizedGuid = hasMasterGuid ? blob.MasterKeyGuid!.Trim().ToLowerInvariant() : string.Empty;
				var key = new MachineGuidKey(blob.MachineId, normalizedGuid);
				var hasRecord = hasMasterGuid && hasMasterKeyRecord.Contains(key);
				var hasCleartext = hasMasterGuid && cleartextMasterKeys.Contains(key);
				var parseFailure = !string.IsNullOrWhiteSpace(blob.ParseFailureReason);
				var unresolved = parseFailure || !hasMasterGuid || !hasCleartext;

				if (!includeResolved && !unresolved)
					continue;

				var blobCount = hasMasterGuid && dependentBlobCount.TryGetValue(key, out var depCount)
					? depCount
					: 0;

				var firstSeen = TboCacheFindingFilters.ParseDateTime(blob.FirstSeenUtc);
				var lastSeen = TboCacheFindingFilters.ParseDateTime(blob.LastSeenUtc);
				var recencyDays = Math.Max(0, (asOf - lastSeen.ToUniversalTime()).TotalDays);

				string? userSid = null;
				string? scope = null;
				if (hasMasterGuid)
				{
					if (sidByMasterKey.TryGetValue(key, out var sid))
						userSid = sid;
					if (scopeByMasterKey.TryGetValue(key, out var resolvedScope))
						scope = resolvedScope;
				}

				var failureReason = blob.ParseFailureReason;
				if (string.IsNullOrWhiteSpace(failureReason))
				{
					if (!hasMasterGuid)
						failureReason = "Blob does not expose a master key GUID.";
					else if (!hasCleartext)
						failureReason = "Master key cleartext not present in cache for this blob.";
					else
						failureReason = "Resolved: matching cleartext master key present in cache.";
				}

				var item = new TboCacheDpapiBacklogItem
				{
					CachePath = resolvedPath,
					BacklogKey = $"BLOB:{blob.DpapiBlobId}",
					ArtifactType = "Blob",
					ArtifactId = blob.DpapiBlobId,
					MachineId = blob.MachineId,
					ServerName = serverName,
					Scope = scope,
					UserSid = userSid,
					MasterKeyGuid = blob.MasterKeyGuid,
					Source = blob.Source,
					Path = blob.Path,
					ValueName = string.IsNullOrWhiteSpace(blob.ValueName) ? null : blob.ValueName,
					HasMasterKeyGuid = hasMasterGuid,
					HasMasterKeyRecord = hasRecord,
					HasCleartextMasterKey = hasCleartext,
					DependentBlobCount = blobCount,
					FailureReason = failureReason!,
					FirstSeenUtc = firstSeen,
					LastSeenUtc = lastSeen,
					RecencyDays = Math.Round(recencyDays, 2, MidpointRounding.AwayFromZero),
				};

				var rankedCandidates = BuildRankedCandidates(item, candidatesByServer, asOf);
				item.CandidateCount = rankedCandidates.Count;
				item.PriorityScore = ComputeBacklogScore(item, unresolved);
				item.Priority = ScoreToPriority(item.PriorityScore);

				results.Add(new BacklogBuildResult
				{
					BacklogItem = item,
					Candidates = rankedCandidates
				});
			}

			return results
				.OrderByDescending(x => x.BacklogItem.PriorityScore)
				.ThenByDescending(x => x.BacklogItem.DependentBlobCount)
				.ThenByDescending(x => x.BacklogItem.LastSeenUtc)
				.ThenBy(x => x.BacklogItem.ServerName, StringComparer.OrdinalIgnoreCase)
				.ThenBy(x => x.BacklogItem.ArtifactType, StringComparer.OrdinalIgnoreCase)
				.ThenBy(x => x.BacklogItem.ArtifactId)
				.ToArray();
		}

		private static IReadOnlyDictionary<string, IReadOnlyList<CandidateAggregate>> BuildCandidateMapByServer(
			TboCacheDatabase db,
			TboCacheDatabase.GraphData graph,
			IReadOnlyDictionary<long, string> serverByMachineId)
		{
			var byServer = new Dictionary<string, Dictionary<string, CandidateAggregate>>(StringComparer.OrdinalIgnoreCase);

			void AddCandidate(
				string serverName,
				string sourceClass,
				string candidateType,
				string candidateValue,
				string? userSid,
				string? userName,
				string sourceKind,
				DateTime observedUtc)
			{
				if (string.IsNullOrWhiteSpace(serverName)
					|| string.IsNullOrWhiteSpace(candidateType)
					|| string.IsNullOrWhiteSpace(candidateValue))
				{
					return;
				}

				var normalizedType = candidateType.Trim();
				var normalizedValue = NormalizeCandidateValue(normalizedType, candidateValue);
				var normalizedSid = string.IsNullOrWhiteSpace(userSid) ? string.Empty : userSid.Trim();
				var key = $"{sourceClass}|{normalizedType}|{normalizedValue}|{normalizedSid}";

				if (!byServer.TryGetValue(serverName, out var map))
				{
					map = new Dictionary<string, CandidateAggregate>(StringComparer.OrdinalIgnoreCase);
					byServer[serverName] = map;
				}

				if (!map.TryGetValue(key, out var existing))
				{
					map[key] = new CandidateAggregate
					{
						SourceClass = sourceClass,
						CandidateType = normalizedType,
						CandidateValue = normalizedValue,
						UserSid = string.IsNullOrWhiteSpace(userSid) ? null : userSid.Trim(),
						UserName = string.IsNullOrWhiteSpace(userName) ? null : userName.Trim(),
						SourceKind = sourceKind ?? string.Empty,
						LastObservedUtc = observedUtc.ToUniversalTime()
					};
					return;
				}

				if (observedUtc.ToUniversalTime() > existing.LastObservedUtc)
				{
					existing.LastObservedUtc = observedUtc.ToUniversalTime();
					existing.SourceKind = sourceKind ?? existing.SourceKind;
				}
			}

			foreach (var machine in graph.Machines)
			{
				var rows = db.QueryVerifiedPasswordHashes(machine.ServerName, userSid: null);
				foreach (var row in rows)
				{
					AddCandidate(
						serverName: machine.ServerName,
						sourceClass: "VerifiedHash",
						candidateType: row.HashType,
						candidateValue: row.HashValueHex,
						userSid: row.UserSid,
						userName: row.UserName,
						sourceKind: $"{row.VerifiedByCmdlet}:{row.VerifiedVia}",
						observedUtc: TboCacheFindingFilters.ParseDateTime(row.LastSeenUtc));
				}
			}

			var principalById = graph.Principals.ToDictionary(x => x.PrincipalId, x => x, EqualityComparer<long>.Default);
			var credentialById = graph.Credentials.ToDictionary(x => x.CredentialId, x => x, EqualityComparer<long>.Default);
			foreach (var observation in graph.Observations)
			{
				if (!observation.PrincipalId.HasValue || !observation.CredentialId.HasValue)
					continue;
				if (!serverByMachineId.TryGetValue(observation.MachineId, out var serverName))
					continue;
				if (!principalById.TryGetValue(observation.PrincipalId.Value, out var principal))
					continue;
				if (string.IsNullOrWhiteSpace(principal.Sid))
					continue;
				if (!credentialById.TryGetValue(observation.CredentialId.Value, out var credential))
					continue;

				if (!string.Equals(credential.Kind, "NTHash", StringComparison.OrdinalIgnoreCase)
					&& !string.Equals(credential.Kind, "Password", StringComparison.OrdinalIgnoreCase))
				{
					continue;
				}

				var sourceClass = string.Equals(credential.Kind, "NTHash", StringComparison.OrdinalIgnoreCase)
					? "ObservedNTHash"
					: "ObservedPassword";

				AddCandidate(
					serverName: serverName,
					sourceClass: sourceClass,
					candidateType: credential.Kind,
					candidateValue: credential.Identifier,
					userSid: principal.Sid,
					userName: principal.Name,
					sourceKind: observation.SourceKind,
					observedUtc: TboCacheFindingFilters.ParseDateTime(observation.ObservedUtc));
			}

			return byServer.ToDictionary(
				x => x.Key,
				x => (IReadOnlyList<CandidateAggregate>)x.Value.Values.ToArray(),
				StringComparer.OrdinalIgnoreCase);
		}

		private static IReadOnlyList<TboCacheDpapiCandidateRanking> BuildRankedCandidates(
			TboCacheDpapiBacklogItem backlog,
			IReadOnlyDictionary<string, IReadOnlyList<CandidateAggregate>> candidatesByServer,
			DateTime asOfUtc)
		{
			if (!candidatesByServer.TryGetValue(backlog.ServerName, out var allServerCandidates))
				return Array.Empty<TboCacheDpapiCandidateRanking>();

			var useFallbackSid = false;
			IReadOnlyList<CandidateAggregate> selected = allServerCandidates;
			if (!string.IsNullOrWhiteSpace(backlog.UserSid))
			{
				var sidMatched = allServerCandidates
					.Where(x => string.Equals(x.UserSid, backlog.UserSid, StringComparison.OrdinalIgnoreCase))
					.ToArray();
				if (sidMatched.Length > 0)
				{
					selected = sidMatched;
				}
				else
				{
					useFallbackSid = true;
				}
			}

			var scored = selected
				.Select(candidate =>
				{
					var sidMatches = !string.IsNullOrWhiteSpace(backlog.UserSid)
						&& string.Equals(backlog.UserSid, candidate.UserSid, StringComparison.OrdinalIgnoreCase);
					var score = ComputeCandidateScore(candidate, backlog, asOfUtc, sidMatches, useFallbackSid);
					return (Candidate: candidate, Score: score, SidMatches: sidMatches);
				})
				.OrderByDescending(x => x.Score)
				.ThenByDescending(x => x.SidMatches)
				.ThenByDescending(x => x.Candidate.LastObservedUtc)
				.ThenBy(x => x.Candidate.SourceClass, StringComparer.OrdinalIgnoreCase)
				.ThenBy(x => x.Candidate.CandidateType, StringComparer.OrdinalIgnoreCase)
				.ThenBy(x => x.Candidate.CandidateValue, StringComparer.OrdinalIgnoreCase)
				.ToArray();

			var results = new List<TboCacheDpapiCandidateRanking>(scored.Length);
			for (var i = 0; i < scored.Length; i++)
			{
				var entry = scored[i];
				var reason = entry.SidMatches
					? "SID match"
					: (useFallbackSid ? "No SID-matched candidates; using host-level fallback." : "Host-level candidate");
				results.Add(new TboCacheDpapiCandidateRanking
				{
					CachePath = backlog.CachePath,
					BacklogKey = backlog.BacklogKey,
					ArtifactType = backlog.ArtifactType,
					ArtifactId = backlog.ArtifactId,
					MachineId = backlog.MachineId,
					ServerName = backlog.ServerName,
					UserSid = backlog.UserSid,
					MasterKeyGuid = backlog.MasterKeyGuid,
					CandidateRank = i + 1,
					CandidateScore = entry.Score,
					CandidatePriority = ScoreToPriority(entry.Score),
					CandidateSourceClass = entry.Candidate.SourceClass,
					CandidateType = entry.Candidate.CandidateType,
					CandidateValue = entry.Candidate.CandidateValue,
					CandidateUserSid = entry.Candidate.UserSid,
					CandidateUserName = entry.Candidate.UserName,
					CandidateSourceKind = entry.Candidate.SourceKind,
					CandidateObservedUtc = entry.Candidate.LastObservedUtc,
					CandidateReason = reason
				});
			}

			return results;
		}

		private static int ComputeBacklogScore(TboCacheDpapiBacklogItem item, bool unresolved)
		{
			var score = item.ArtifactType.Equals("MasterKey", StringComparison.OrdinalIgnoreCase) ? 45 : 30;
			if (unresolved)
				score += 20;
			if (item.DependentBlobCount > 0)
				score += (int)Math.Min(30, item.DependentBlobCount * 6);
			if (!string.IsNullOrWhiteSpace(item.UserSid))
				score += 8;
			if (!item.HasMasterKeyGuid)
				score += 6;
			if (!item.HasMasterKeyRecord && item.HasMasterKeyGuid)
				score += 6;
			if (item.RecencyDays <= 1)
				score += 18;
			else if (item.RecencyDays <= 7)
				score += 14;
			else if (item.RecencyDays <= 30)
				score += 10;
			else if (item.RecencyDays <= 90)
				score += 5;

			return Math.Clamp(score, 0, 100);
		}

		private static int ComputeCandidateScore(
			CandidateAggregate candidate,
			TboCacheDpapiBacklogItem backlog,
			DateTime asOfUtc,
			bool sidMatches,
			bool sidFallback)
		{
			var score = candidate.SourceClass switch
			{
				"VerifiedHash" => 100,
				"ObservedNTHash" => 72,
				"ObservedPassword" => 60,
				_ => 50,
			};

			if (candidate.CandidateType.Equals("nt_pwd", StringComparison.OrdinalIgnoreCase)
				|| candidate.CandidateType.Equals("NTHash", StringComparison.OrdinalIgnoreCase))
			{
				score += 8;
			}
			else if (candidate.CandidateType.Equals("sha1_pwd", StringComparison.OrdinalIgnoreCase))
			{
				score += 6;
			}

			var recencyDays = Math.Max(0, (asOfUtc.ToUniversalTime() - candidate.LastObservedUtc.ToUniversalTime()).TotalDays);
			if (recencyDays <= 1)
				score += 20;
			else if (recencyDays <= 7)
				score += 15;
			else if (recencyDays <= 30)
				score += 10;
			else if (recencyDays <= 90)
				score += 5;
			else
				score += 1;

			if (!string.IsNullOrWhiteSpace(backlog.UserSid))
			{
				if (sidMatches)
					score += 12;
				else if (sidFallback)
					score -= 15;
			}

			return Math.Clamp(score, 0, 200);
		}

		private static string NormalizeCandidateValue(string candidateType, string value)
		{
			if (string.IsNullOrWhiteSpace(value))
				return string.Empty;

			if (candidateType.Contains("hash", StringComparison.OrdinalIgnoreCase)
				|| candidateType.Contains("nt_pwd", StringComparison.OrdinalIgnoreCase)
				|| candidateType.Contains("sha1_pwd", StringComparison.OrdinalIgnoreCase))
			{
				return value.Trim().ToLowerInvariant();
			}

			return value.Trim();
		}

		private static string ScoreToPriority(int score)
		{
			if (score >= 120)
				return "Critical";
			if (score >= 90)
				return "High";
			if (score >= 60)
				return "Medium";
			if (score >= 30)
				return "Low";
			return "Informational";
		}

		private sealed class MachineGuidKeyComparer : IEqualityComparer<MachineGuidKey>
		{
			public bool Equals(MachineGuidKey x, MachineGuidKey y)
				=> x.MachineId == y.MachineId
					&& string.Equals(x.MasterKeyGuid, y.MasterKeyGuid, StringComparison.OrdinalIgnoreCase);

			public int GetHashCode(MachineGuidKey obj)
			{
				var h1 = obj.MachineId.GetHashCode();
				var h2 = StringComparer.OrdinalIgnoreCase.GetHashCode(obj.MasterKeyGuid ?? string.Empty);
				return HashCode.Combine(h1, h2);
			}
		}
	}

	[Cmdlet(VerbsCommon.Get, "TBOCacheInfo")]
	[OutputType(typeof(TboCacheInfo))]
	public sealed class GetTBOCacheInfo : PSCmdlet
	{
		[Parameter]
		public string? Path { get; set; }

		protected override void ProcessRecord()
		{
			var resolvedPath = TboCacheDatabase.ResolveCachePath(this.Path);
			using var db = TboCacheDatabase.Open(this.Path, msg => this.WriteVerbose(msg));

			var (schemaVersion, _) = db.GetInfo(this.Path);
			var counts = db.GetCountsByTable();

			long GetCount(string table)
				=> counts.TryGetValue(table, out var count) ? count : 0;

			this.WriteObject(new TboCacheInfo
			{
				Path = resolvedPath,
				SchemaVersion = schemaVersion,
				MachineCount = GetCount("machines"),
				PrincipalCount = GetCount("principals"),
				CredentialCount = GetCount("credentials"),
				ObservationCount = GetCount("observations"),
				DpapiMasterKeyCount = GetCount("dpapi_masterkeys"),
				DpapiBlobCount = GetCount("dpapi_blobs"),
				WriteActivityCount = GetCount("write_activities"),
			});
		}
	}

	[Cmdlet(VerbsCommon.Clear, "TBOCache", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High)]
	public sealed class ClearTBOCache : PSCmdlet
	{
		[Parameter]
		public string? Path { get; set; }

		protected override void ProcessRecord()
		{
			var resolvedPath = TboCacheDatabase.ResolveCachePath(this.Path);

			if (!this.ShouldProcess(resolvedPath, "Clear cache database (delete all rows)"))
				return;

			using var db = TboCacheDatabase.Open(this.Path, msg => this.WriteVerbose(msg));
			db.ClearAll();
		}
	}

	[Cmdlet(VerbsCommon.Remove, "TBOCacheEntry", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High)]
	public sealed class RemoveTBOCacheEntry : PSCmdlet
	{
		private readonly List<long> _ids = new();

		[Parameter(Mandatory = true)]
		public TboCacheEntryType Type { get; set; }

		[Parameter(Mandatory = true, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
		public long[] Id { get; set; } = Array.Empty<long>();

		[Parameter]
		public string? Path { get; set; }

		protected override void ProcessRecord()
		{
			foreach (var id in this.Id ?? Array.Empty<long>())
			{
				if (id <= 0)
				{
					this.WriteError(new ErrorRecord(
						new ArgumentOutOfRangeException(nameof(this.Id), id, "Id must be a positive integer."),
						"TBOCacheEntryInvalidId",
						ErrorCategory.InvalidArgument,
						id));
					continue;
				}

				_ids.Add(id);
			}
		}

		protected override void EndProcessing()
		{
			if (_ids.Count == 0)
				return;

			var resolvedPath = TboCacheDatabase.ResolveCachePath(this.Path);
			var unique = _ids.Distinct().OrderBy(x => x).ToArray();

			if (!this.ShouldProcess(resolvedPath, $"Remove {this.Type} entries: {string.Join(", ", unique)}"))
				return;

			using var db = TboCacheDatabase.Open(this.Path, msg => this.WriteVerbose(msg));
			db.RemoveEntries(this.Type, unique);
		}
	}

	[Cmdlet(VerbsCommon.Get, "TBOCacheCredentialReuse")]
	[OutputType(typeof(TboCacheCredentialReuse), typeof(TboCacheCredentialReuseHeatmap), typeof(TboCacheCredentialBlastRadius))]
	public sealed class GetTBOCacheCredentialReuse : PSCmdlet
	{
		[Parameter]
		public string? Kind { get; set; }

		[Parameter]
		public string? Identifier { get; set; }

		[Parameter]
		[ValidateRange(2, int.MaxValue)]
		public int MinimumMachineCount { get; set; } = 2;

		[Parameter]
		public TboCacheCredentialReuseView View { get; set; } = TboCacheCredentialReuseView.Detail;

		[Parameter]
		[ValidateRange(0, int.MaxValue)]
		public int Top { get; set; }

		[Parameter]
		public DateTime? AsOfUtc { get; set; }

		[Parameter]
		public string? Path { get; set; }

		protected override void ProcessRecord()
		{
			using var db = TboCacheDatabase.Open(this.Path, msg => this.WriteVerbose(msg));
			var rows = db.QueryCredentialReuse(this.Kind, this.Identifier, this.MinimumMachineCount);

			if (this.View == TboCacheCredentialReuseView.Heatmap)
			{
				if (this.Top > 0)
					this.WriteVerbose("Get-TBOCacheCredentialReuse: -Top is only applied in -View BlastRadius mode and is ignored for Heatmap.");
				if (this.AsOfUtc.HasValue)
					this.WriteVerbose("Get-TBOCacheCredentialReuse: -AsOfUtc is only applied in -View BlastRadius mode and is ignored for Heatmap.");

				foreach (var heatmap in TboCacheCredentialReuseAnalysis.BuildHeatmap(rows))
				{
					this.WriteObject(heatmap);
				}

				return;
			}

			if (this.View == TboCacheCredentialReuseView.BlastRadius)
			{
				var asOf = (this.AsOfUtc ?? DateTime.UtcNow).ToUniversalTime();
				var ranked = TboCacheCredentialReuseAnalysis.BuildBlastRadius(rows, asOf);
				if (this.Top > 0)
					ranked = ranked.Take(this.Top).ToArray();

				foreach (var blast in ranked)
				{
					this.WriteObject(blast);
				}

				return;
			}

			foreach (var row in rows)
			{
				this.WriteObject(new TboCacheCredentialReuse
				{
					CredentialId = row.CredentialId,
					CredentialKind = row.Kind,
					CredentialIdentifier = row.Identifier,
					MachineCount = row.MachineCount,

					ServerName = row.ServerName,
					PrincipalSid = row.PrincipalSid,
					PrincipalDomain = row.PrincipalDomain,
					PrincipalName = row.PrincipalName,
					PrincipalType = row.PrincipalType,

					ObservationCount = row.ObservationCount,
					FirstObservedUtc = ParseDateTime(row.FirstObservedUtc),
					LastObservedUtc = ParseDateTime(row.LastObservedUtc),
				});
			}
		}

		private static DateTime ParseDateTime(string value)
		{
			if (string.IsNullOrWhiteSpace(value))
				return default;

			if (DateTime.TryParseExact(
				value,
				"O",
				CultureInfo.InvariantCulture,
				DateTimeStyles.RoundtripKind,
				out var parsed))
			{
				return parsed;
			}

			return DateTime.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
		}
	}

	[Cmdlet(VerbsCommon.Get, "TBOCacheDpapiBacklog")]
	[OutputType(typeof(TboCacheDpapiBacklogItem), typeof(TboCacheDpapiCandidateRanking))]
	public sealed class GetTBOCacheDpapiBacklog : PSCmdlet
	{
		[Parameter(Position = 0)]
		public string[]? ServerName { get; set; }

		[Parameter]
		public string[]? UserSid { get; set; }

		[Parameter]
		public TboCacheDpapiBacklogView View { get; set; } = TboCacheDpapiBacklogView.Backlog;

		[Parameter]
		[ValidateRange(1, int.MaxValue)]
		public int Top { get; set; } = 5;

		[Parameter]
		public DateTime? AsOfUtc { get; set; }

		[Parameter]
		public SwitchParameter IncludeResolved { get; set; }

		[Parameter]
		public string? Path { get; set; }

		protected override void ProcessRecord()
		{
			var resolvedPath = TboCacheDatabase.ResolveCachePath(this.Path);
			var asOf = (this.AsOfUtc ?? DateTime.UtcNow).ToUniversalTime();

			using var db = TboCacheDatabase.Open(this.Path, msg => this.WriteVerbose(msg));
			var built = TboCacheDpapiBacklogAnalysis.Build(
				db,
				resolvedPath,
				asOf,
				includeResolved: this.IncludeResolved.IsPresent);

			var serverPatterns = TboCacheFindingFilters.BuildPatterns(this.ServerName);
			var sidPatterns = TboCacheFindingFilters.BuildPatterns(this.UserSid);

			var filtered = built.Where(x =>
				TboCacheFindingFilters.MatchesAny(x.BacklogItem.ServerName, serverPatterns)
				&& TboCacheFindingFilters.MatchesAny(x.BacklogItem.UserSid, sidPatterns));

			if (this.View == TboCacheDpapiBacklogView.CandidateRanking)
			{
				foreach (var entry in filtered)
				{
					foreach (var candidate in entry.Candidates.Take(this.Top))
						this.WriteObject(candidate);
				}
				return;
			}

			if (this.Top != 5)
				this.WriteVerbose("Get-TBOCacheDpapiBacklog: -Top is only applied in -View CandidateRanking mode and is ignored for Backlog.");

			foreach (var entry in filtered)
				this.WriteObject(entry.BacklogItem);
		}
	}

	[Cmdlet(VerbsCommon.Get, "TBOCacheMachineFindings")]
	[OutputType(typeof(TboCacheFinding))]
	public sealed class GetTBOCacheMachineFindings : PSCmdlet
	{
		[Parameter(Position = 0)]
		public string[]? ServerName { get; set; }

		[Parameter]
		public string[]? SourceKind { get; set; }

		[Parameter]
		public string[]? SourcePath { get; set; }

		[Parameter]
		public string? Path { get; set; }

		protected override void ProcessRecord()
		{
			var resolvedPath = TboCacheDatabase.ResolveCachePath(this.Path);
			using var db = TboCacheDatabase.Open(this.Path, msg => this.WriteVerbose(msg));

			var rows = db.QueryObservationFindings(
				serverName: TboCacheFindingFilters.GetSingleExactFilter(this.ServerName),
				sourceKind: TboCacheFindingFilters.GetSingleExactFilter(this.SourceKind),
				sourcePath: TboCacheFindingFilters.GetSingleExactFilter(this.SourcePath));

			var serverPatterns = TboCacheFindingFilters.BuildPatterns(this.ServerName);
			var sourceKindPatterns = TboCacheFindingFilters.BuildPatterns(this.SourceKind);
			var sourcePathPatterns = TboCacheFindingFilters.BuildPatterns(this.SourcePath);

			foreach (var row in rows)
			{
				if (!TboCacheFindingFilters.MatchesAny(row.ServerName, serverPatterns))
					continue;
				if (!TboCacheFindingFilters.MatchesAny(row.SourceKind, sourceKindPatterns))
					continue;
				if (!TboCacheFindingFilters.MatchesAny(row.SourcePath, sourcePathPatterns))
					continue;

				this.WriteObject(TboCacheFindingFilters.ToFinding(resolvedPath, row));
			}
		}
	}

	[Cmdlet(VerbsCommon.Get, "TBOCachePrincipalFindings")]
	[OutputType(typeof(TboCacheFinding))]
	public sealed class GetTBOCachePrincipalFindings : PSCmdlet
	{
		[Parameter]
		public string[]? Sid { get; set; }

		[Parameter]
		public string[]? Domain { get; set; }

		[Parameter]
		public string[]? Name { get; set; }

		[Parameter]
		public string[]? Type { get; set; }

		[Parameter]
		public string[]? ServerName { get; set; }

		[Parameter]
		public string? Path { get; set; }

		protected override void ProcessRecord()
		{
			var resolvedPath = TboCacheDatabase.ResolveCachePath(this.Path);
			using var db = TboCacheDatabase.Open(this.Path, msg => this.WriteVerbose(msg));

			var rows = db.QueryObservationFindings(
				serverName: TboCacheFindingFilters.GetSingleExactFilter(this.ServerName),
				principalSid: TboCacheFindingFilters.GetSingleExactFilter(this.Sid),
				principalDomain: TboCacheFindingFilters.GetSingleExactFilter(this.Domain),
				principalName: TboCacheFindingFilters.GetSingleExactFilter(this.Name),
				principalType: TboCacheFindingFilters.GetSingleExactFilter(this.Type));

			var serverPatterns = TboCacheFindingFilters.BuildPatterns(this.ServerName);
			var sidPatterns = TboCacheFindingFilters.BuildPatterns(this.Sid);
			var domainPatterns = TboCacheFindingFilters.BuildPatterns(this.Domain);
			var namePatterns = TboCacheFindingFilters.BuildPatterns(this.Name);
			var typePatterns = TboCacheFindingFilters.BuildPatterns(this.Type);

			foreach (var row in rows)
			{
				if (!TboCacheFindingFilters.MatchesAny(row.ServerName, serverPatterns))
					continue;
				if (!TboCacheFindingFilters.MatchesAny(row.PrincipalSid, sidPatterns))
					continue;
				if (!TboCacheFindingFilters.MatchesAny(row.PrincipalDomain, domainPatterns))
					continue;
				if (!TboCacheFindingFilters.MatchesAny(row.PrincipalName, namePatterns))
					continue;
				if (!TboCacheFindingFilters.MatchesAny(row.PrincipalType, typePatterns))
					continue;

				this.WriteObject(TboCacheFindingFilters.ToFinding(resolvedPath, row));
			}
		}
	}

	[Cmdlet(VerbsCommon.Get, "TBOCacheCredentialFindings")]
	[OutputType(typeof(TboCacheFinding))]
	public sealed class GetTBOCacheCredentialFindings : PSCmdlet
	{
		[Parameter]
		public string[]? Kind { get; set; }

		[Parameter]
		public string[]? Identifier { get; set; }

		[Parameter]
		public string[]? ServerName { get; set; }

		[Parameter]
		public string? Path { get; set; }

		protected override void ProcessRecord()
		{
			var resolvedPath = TboCacheDatabase.ResolveCachePath(this.Path);
			using var db = TboCacheDatabase.Open(this.Path, msg => this.WriteVerbose(msg));

			var rows = db.QueryObservationFindings(
				serverName: TboCacheFindingFilters.GetSingleExactFilter(this.ServerName),
				credentialKind: TboCacheFindingFilters.GetSingleExactFilter(this.Kind),
				credentialIdentifier: TboCacheFindingFilters.GetSingleExactFilter(this.Identifier));

			var serverPatterns = TboCacheFindingFilters.BuildPatterns(this.ServerName);
			var kindPatterns = TboCacheFindingFilters.BuildPatterns(this.Kind);
			var identifierPatterns = TboCacheFindingFilters.BuildPatterns(this.Identifier);

			foreach (var row in rows)
			{
				if (!TboCacheFindingFilters.MatchesAny(row.ServerName, serverPatterns))
					continue;
				if (!TboCacheFindingFilters.MatchesAny(row.CredentialKind, kindPatterns))
					continue;
				if (!TboCacheFindingFilters.MatchesAny(row.CredentialIdentifier, identifierPatterns))
					continue;

				this.WriteObject(TboCacheFindingFilters.ToFinding(resolvedPath, row));
			}
		}
	}

	[Cmdlet(VerbsCommon.Get, "TBOCachePathFindings")]
	[OutputType(typeof(TboCacheFinding))]
	public sealed class GetTBOCachePathFindings : PSCmdlet
	{
		[Parameter(Mandatory = true, Position = 0)]
		[ValidateNotNullOrEmpty]
		public string[] SourcePath { get; set; } = Array.Empty<string>();

		[Parameter]
		public string[]? ServerName { get; set; }

		[Parameter]
		public string[]? SourceKind { get; set; }

		[Parameter]
		public string? Path { get; set; }

		protected override void ProcessRecord()
		{
			var resolvedPath = TboCacheDatabase.ResolveCachePath(this.Path);
			using var db = TboCacheDatabase.Open(this.Path, msg => this.WriteVerbose(msg));

			var rows = db.QueryObservationFindings(
				serverName: TboCacheFindingFilters.GetSingleExactFilter(this.ServerName),
				sourceKind: TboCacheFindingFilters.GetSingleExactFilter(this.SourceKind),
				sourcePath: TboCacheFindingFilters.GetSingleExactFilter(this.SourcePath));

			var pathPatterns = TboCacheFindingFilters.BuildPatterns(this.SourcePath);
			var serverPatterns = TboCacheFindingFilters.BuildPatterns(this.ServerName);
			var sourceKindPatterns = TboCacheFindingFilters.BuildPatterns(this.SourceKind);

			foreach (var row in rows)
			{
				if (!TboCacheFindingFilters.MatchesAny(row.SourcePath, pathPatterns))
					continue;
				if (!TboCacheFindingFilters.MatchesAny(row.ServerName, serverPatterns))
					continue;
				if (!TboCacheFindingFilters.MatchesAny(row.SourceKind, sourceKindPatterns))
					continue;

				this.WriteObject(TboCacheFindingFilters.ToFinding(resolvedPath, row));
			}
		}
	}

	[Cmdlet(VerbsData.Export, "TBOCacheGraph")]
	[OutputType(typeof(string))]
	public sealed class ExportTBOCacheGraph : PSCmdlet
	{
		[Parameter]
		public TboCacheGraphFormat Format { get; set; } = TboCacheGraphFormat.Json;

		[Parameter]
		public string? Path { get; set; }

		protected override void ProcessRecord()
		{
			using var db = TboCacheDatabase.Open(this.Path, msg => this.WriteVerbose(msg));
			var graph = db.QueryGraphData();

			var output = this.Format switch
			{
				TboCacheGraphFormat.Dot => RenderDot(graph),
				TboCacheGraphFormat.OpenGraph => RenderOpenGraph(graph),
				_ => RenderJson(graph)
			};

			this.WriteObject(output);
		}

		// BloodHound OpenGraph JSON export.
		//
		// Schema reference: https://bloodhound.specterops.io/opengraph/schema
		//
		// Important constraints:
		// - Node.id is a string and must be unique.
		// - Node.kinds is a string array (1..3 items). The first element is treated as the "primary" kind.
		// - Node/Edge properties is a flat key-value map where values must not be objects
		//   (strings, numbers, booleans, or arrays of primitives only).
		private static string RenderOpenGraph(TboCacheDatabase.GraphData graph)
		{
			using var ms = new MemoryStream();

			var principalNodeIds = BuildPrincipalNodeIds(graph);

			using (var writer = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true }))
			{
				writer.WriteStartObject();

				writer.WriteStartObject("graph");

				writer.WriteStartArray("nodes");

				foreach (var m in graph.Machines)
					WriteOpenGraphMachineNode(writer, m);

				foreach (var p in graph.Principals)
					WriteOpenGraphPrincipalNode(writer, p, principalNodeIds);

				foreach (var c in graph.Credentials)
					WriteOpenGraphCredentialNode(writer, c);

				writer.WriteEndArray();

				writer.WriteStartArray("edges");

				foreach (var o in graph.Observations)
				{
					if (o.PrincipalId.HasValue)
					{
						WriteOpenGraphObservationEdge(
							writer,
							o,
							edgeKind: "ObservedPrincipal",
							targetNodeId: ResolvePrincipalNodeId(principalNodeIds, o.PrincipalId.Value),
							targetKind: "TBO.Principal");
					}

					if (o.CredentialId.HasValue)
					{
						WriteOpenGraphObservationEdge(
							writer,
							o,
							edgeKind: "ObservedCredential",
							targetNodeId: $"credential:{o.CredentialId.Value}",
							targetKind: "TBO.Credential");
					}
				}

				writer.WriteEndArray();

				writer.WriteEndObject(); // graph
				writer.WriteEndObject(); // root
			}

			return Encoding.UTF8.GetString(ms.ToArray());
		}

		private static void WriteOpenGraphMachineNode(Utf8JsonWriter writer, TboCacheDatabase.GraphMachineRow m)
		{
			writer.WriteStartObject();
			writer.WriteString("id", $"machine:{m.MachineId}");

			// Keep the primary kind generic for UI readability, while preserving a TBO-specific kind for filtering.
			writer.WriteStartArray("kinds");
			writer.WriteStringValue("Computer");
			writer.WriteStringValue("TBO.Machine");
			writer.WriteEndArray();

			writer.WriteStartObject("properties");
			writer.WriteString("objectid", $"machine:{m.MachineId}");
			writer.WriteNumber("machineId", m.MachineId);
			writer.WriteString("serverName", m.ServerName);
			writer.WriteString("name", m.ServerName);
			writer.WriteString("displayname", m.ServerName);
			writer.WriteString("firstSeenUtc", m.FirstSeenUtc);
			writer.WriteString("lastSeenUtc", m.LastSeenUtc);
			writer.WriteEndObject();

			writer.WriteEndObject();
		}

		private static void WriteOpenGraphPrincipalNode(
			Utf8JsonWriter writer,
			TboCacheDatabase.GraphPrincipalRow p,
			IReadOnlyDictionary<long, string> principalNodeIds)
		{
			var nodeId = ResolvePrincipalNodeId(principalNodeIds, p.PrincipalId);

			writer.WriteStartObject();
			writer.WriteString("id", nodeId);

			var primaryKind = MapPrincipalKind(p.Type);

			writer.WriteStartArray("kinds");
			writer.WriteStringValue(primaryKind);
			if (!string.Equals(primaryKind, "TBO.Principal", StringComparison.Ordinal))
				writer.WriteStringValue("TBO.Principal");
			writer.WriteEndArray();

			var display = BuildPrincipalDisplay(p.PrincipalId, p.Sid, p.Domain, p.Name);

			writer.WriteStartObject("properties");
			writer.WriteString("objectid", nodeId);
			writer.WriteNumber("principalId", p.PrincipalId);
			writer.WriteString("name", display);
			writer.WriteString("displayname", display);
			if (!string.IsNullOrWhiteSpace(p.Sid))
				writer.WriteString("sid", p.Sid);
			if (!string.IsNullOrWhiteSpace(p.Domain))
				writer.WriteString("domain", p.Domain);
			if (!string.IsNullOrWhiteSpace(p.Name))
				writer.WriteString("accountName", p.Name);
			if (!string.IsNullOrWhiteSpace(p.Type))
				writer.WriteString("principalType", p.Type);
			writer.WriteString("firstSeenUtc", p.FirstSeenUtc);
			writer.WriteString("lastSeenUtc", p.LastSeenUtc);
			writer.WriteEndObject();

			writer.WriteEndObject();
		}

		private static void WriteOpenGraphCredentialNode(Utf8JsonWriter writer, TboCacheDatabase.GraphCredentialRow c)
		{
			writer.WriteStartObject();
			writer.WriteString("id", $"credential:{c.CredentialId}");

			writer.WriteStartArray("kinds");
			writer.WriteStringValue("TBO.Credential");
			writer.WriteEndArray();

			var display = $"{c.Kind}:{c.Identifier}";

			writer.WriteStartObject("properties");
			writer.WriteString("objectid", $"credential:{c.CredentialId}");
			writer.WriteNumber("credentialId", c.CredentialId);
			writer.WriteString("kind", c.Kind);
			writer.WriteString("identifier", c.Identifier);
			writer.WriteString("name", display);
			writer.WriteString("displayname", display);
			writer.WriteString("firstSeenUtc", c.FirstSeenUtc);
			writer.WriteString("lastSeenUtc", c.LastSeenUtc);
			writer.WriteEndObject();

			writer.WriteEndObject();
		}

		private static void WriteOpenGraphObservationEdge(
			Utf8JsonWriter writer,
			TboCacheDatabase.GraphObservationRow o,
			string edgeKind,
			string targetNodeId,
			string targetKind)
		{
			writer.WriteStartObject();
			writer.WriteString("kind", edgeKind);

			writer.WriteStartObject("start");
			writer.WriteString("match_by", "id");
			writer.WriteString("value", $"machine:{o.MachineId}");
			writer.WriteString("kind", "TBO.Machine");
			writer.WriteEndObject();

			writer.WriteStartObject("end");
			writer.WriteString("match_by", "id");
			writer.WriteString("value", targetNodeId);
			writer.WriteString("kind", targetKind);
			writer.WriteEndObject();

			// Keep properties flat (no nested objects), per OpenGraph schema requirements.
			writer.WriteStartObject("properties");
			writer.WriteNumber("observationId", o.ObservationId);
			writer.WriteString("observedUtc", o.ObservedUtc);
			writer.WriteString("sourceKind", o.SourceKind);
			if (!string.IsNullOrWhiteSpace(o.SourcePath))
				writer.WriteString("sourcePath", o.SourcePath);
			if (o.Confidence.HasValue)
				writer.WriteNumber("confidence", o.Confidence.Value);
			if (!string.IsNullOrWhiteSpace(o.ContextJson))
				writer.WriteString("contextJson", o.ContextJson);
			writer.WriteEndObject();

			writer.WriteEndObject();
		}

		private static string MapPrincipalKind(string? principalType)
		{
			if (string.IsNullOrWhiteSpace(principalType))
				return "TBO.Principal";

			// These are just for better UI icons/labels in BloodHound; they are not semantics for TBO.
			return principalType.Trim() switch
			{
				"User" => "User",
				"Group" => "Group",
				"Computer" => "Computer",
				_ => "TBO.Principal"
			};
		}

		private static string BuildPrincipalDisplay(long principalId, string? sid, string? domain, string? name)
		{
			var dn = string.IsNullOrWhiteSpace(domain) || string.IsNullOrWhiteSpace(name)
				? null
				: $"{domain}\\{name}";

			if (!string.IsNullOrWhiteSpace(dn))
				return dn;

			if (!string.IsNullOrWhiteSpace(sid))
				return sid;

			return $"principal:{principalId}";
		}

		private static string RenderJson(TboCacheDatabase.GraphData graph)
		{
			using var ms = new MemoryStream();

			var principalNodeIds = BuildPrincipalNodeIds(graph);

			using (var writer = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true }))
			{
				writer.WriteStartObject();
				writer.WriteString("schema", "tbo.cache.graph.v2");

				writer.WriteStartArray("nodes");
				foreach (var m in graph.Machines)
				{
					writer.WriteStartObject();
					writer.WriteString("id", $"machine:{m.MachineId}");
					writer.WriteString("type", "machine");
					writer.WriteNumber("machineId", m.MachineId);
					writer.WriteString("serverName", m.ServerName);
					writer.WriteString("firstSeenUtc", m.FirstSeenUtc);
					writer.WriteString("lastSeenUtc", m.LastSeenUtc);
					writer.WriteEndObject();
				}

				foreach (var p in graph.Principals)
				{
					var nodeId = ResolvePrincipalNodeId(principalNodeIds, p.PrincipalId);
					writer.WriteStartObject();
					writer.WriteString("id", nodeId);
					writer.WriteString("type", "principal");
					writer.WriteNumber("principalId", p.PrincipalId);
					writer.WriteString("scope", p.Scope);
					if (p.ScopeMachineId.HasValue)
						writer.WriteNumber("scopeMachineId", p.ScopeMachineId.Value);
					if (!string.IsNullOrWhiteSpace(p.Sid))
						writer.WriteString("sid", p.Sid);
					if (!string.IsNullOrWhiteSpace(p.Domain))
						writer.WriteString("domain", p.Domain);
					if (!string.IsNullOrWhiteSpace(p.Name))
						writer.WriteString("name", p.Name);
					if (!string.IsNullOrWhiteSpace(p.Type))
						writer.WriteString("principalType", p.Type);
					writer.WriteString("firstSeenUtc", p.FirstSeenUtc);
					writer.WriteString("lastSeenUtc", p.LastSeenUtc);
					writer.WriteEndObject();
				}

				foreach (var c in graph.Credentials)
				{
					writer.WriteStartObject();
					writer.WriteString("id", $"credential:{c.CredentialId}");
					writer.WriteString("type", "credential");
					writer.WriteNumber("credentialId", c.CredentialId);
					writer.WriteString("kind", c.Kind);
					writer.WriteString("identifier", c.Identifier);
					writer.WriteString("firstSeenUtc", c.FirstSeenUtc);
					writer.WriteString("lastSeenUtc", c.LastSeenUtc);
					writer.WriteEndObject();
				}
				writer.WriteEndArray();

				writer.WriteStartArray("edges");
				foreach (var o in graph.Observations)
				{
					if (o.PrincipalId.HasValue)
					{
						WriteObservationEdge(
							writer,
							o,
							edgeKind: "observed_principal",
							edgeIdSuffix: "principal",
							targetNodeId: ResolvePrincipalNodeId(principalNodeIds, o.PrincipalId.Value));
					}

					if (o.CredentialId.HasValue)
					{
						WriteObservationEdge(
							writer,
							o,
							edgeKind: "observed_credential",
							edgeIdSuffix: "credential",
							targetNodeId: $"credential:{o.CredentialId.Value}");
					}
				}
				writer.WriteEndArray();

				writer.WriteEndObject();
			}

			return Encoding.UTF8.GetString(ms.ToArray());
		}

		private static void WriteObservationEdge(
			Utf8JsonWriter writer,
			TboCacheDatabase.GraphObservationRow o,
			string edgeKind,
			string edgeIdSuffix,
			string targetNodeId)
		{
			writer.WriteStartObject();
			writer.WriteString("id", $"observation:{o.ObservationId}:{edgeIdSuffix}");
			writer.WriteString("type", edgeKind);
			writer.WriteNumber("observationId", o.ObservationId);
			writer.WriteString("source", $"machine:{o.MachineId}");
			writer.WriteString("target", targetNodeId);
			writer.WriteString("observedUtc", o.ObservedUtc);
			writer.WriteString("sourceKind", o.SourceKind);
			if (!string.IsNullOrWhiteSpace(o.SourcePath))
				writer.WriteString("sourcePath", o.SourcePath);
			if (o.Confidence.HasValue)
				writer.WriteNumber("confidence", o.Confidence.Value);
			if (!string.IsNullOrWhiteSpace(o.ContextJson))
				writer.WriteString("contextJson", o.ContextJson);
			writer.WriteEndObject();
		}

		private static string RenderDot(TboCacheDatabase.GraphData graph)
		{
			var sb = new StringBuilder();
			sb.AppendLine("digraph tbo_cache {");
			sb.AppendLine("  rankdir=LR;");
			sb.AppendLine("  node [fontname=\"Consolas\", fontsize=10];");
			sb.AppendLine("  edge [fontname=\"Consolas\", fontsize=9];");
			sb.AppendLine();

			var dotPrincipalNodeIds = new Dictionary<long, string>();
			foreach (var p in graph.Principals)
				dotPrincipalNodeIds[p.PrincipalId] = GetDotPrincipalNodeId(p);

			foreach (var m in graph.Machines)
			{
				var label = $"machine\\n{m.ServerName}";
				sb.AppendLine($"  m{m.MachineId} [shape=box, label=\"{DotEscape(label)}\"];");
			}

			foreach (var p in graph.Principals)
			{
				var nodeId = dotPrincipalNodeIds[p.PrincipalId];
				var display = GetPrincipalDisplay(p.PrincipalId, p.Sid, p.Domain, p.Name);
				var label = string.IsNullOrWhiteSpace(p.Type)
					? $"principal\\n{display}"
					: $"principal ({p.Type})\\n{display}";
				sb.AppendLine($"  {nodeId} [shape=ellipse, label=\"{DotEscape(label)}\"];");
			}

			foreach (var c in graph.Credentials)
			{
				var label = $"credential ({c.Kind})\\n{c.Identifier}";
				sb.AppendLine($"  c{c.CredentialId} [shape=diamond, label=\"{DotEscape(label)}\"];");
			}

			sb.AppendLine();

			foreach (var o in graph.Observations)
			{
				var label = BuildObservationEdgeLabel(o);

				if (o.PrincipalId.HasValue)
				{
					var principalNodeId = dotPrincipalNodeIds.TryGetValue(o.PrincipalId.Value, out var nodeId)
						? nodeId
						: $"pg{o.PrincipalId.Value}";
					sb.AppendLine($"  m{o.MachineId} -> {principalNodeId} [label=\"{DotEscape(label)}\"];");
				}

				if (o.CredentialId.HasValue)
					sb.AppendLine($"  m{o.MachineId} -> c{o.CredentialId.Value} [label=\"{DotEscape(label)}\"];");
			}

			sb.AppendLine("}");
			return sb.ToString();
		}

		private static string BuildObservationEdgeLabel(TboCacheDatabase.GraphObservationRow o)
		{
			if (o.Confidence.HasValue)
				return $"obs {o.ObservationId}\\n{o.SourceKind}\\n{o.ObservedUtc}\\nconf={o.Confidence.Value}";

			return $"obs {o.ObservationId}\\n{o.SourceKind}\\n{o.ObservedUtc}";
		}

		private static string GetPrincipalDisplay(long principalId, string? sid, string? domain, string? name)
		{
			var dn = string.IsNullOrWhiteSpace(domain) || string.IsNullOrWhiteSpace(name)
				? null
				: $"{domain}\\{name}";

			if (!string.IsNullOrWhiteSpace(dn) && !string.IsNullOrWhiteSpace(sid))
				return $"{dn}\\n{sid}";

			if (!string.IsNullOrWhiteSpace(dn))
				return dn;

			if (!string.IsNullOrWhiteSpace(sid))
				return sid;

			return $"principal:{principalId}";
		}

		private static string DotEscape(string value)
		{
			if (value == null)
				return string.Empty;

			return value
				.Replace("\\", "\\\\", StringComparison.Ordinal)
				.Replace("\"", "\\\"", StringComparison.Ordinal)
				.Replace("\r", string.Empty, StringComparison.Ordinal)
				.Replace("\n", "\\n", StringComparison.Ordinal);
		}

		private static IReadOnlyDictionary<long, string> BuildPrincipalNodeIds(TboCacheDatabase.GraphData graph)
		{
			var ids = new Dictionary<long, string>();
			foreach (var p in graph.Principals)
				ids[p.PrincipalId] = GetPrincipalNodeId(p);

			return ids;
		}

		private static string ResolvePrincipalNodeId(IReadOnlyDictionary<long, string> principalNodeIds, long principalId)
		{
			if (principalNodeIds.TryGetValue(principalId, out var nodeId))
				return nodeId;

			// Fallback for inconsistent caches.
			return $"principal:unknown:{principalId}";
		}

		private static string GetPrincipalNodeId(TboCacheDatabase.GraphPrincipalRow p)
		{
			if (string.Equals(p.Scope, "Machine", StringComparison.OrdinalIgnoreCase))
			{
				var machinePart = p.ScopeMachineId.HasValue
					? p.ScopeMachineId.Value.ToString(CultureInfo.InvariantCulture)
					: "0";
				return $"principal:machine:{machinePart}:{p.PrincipalId}";
			}

			return $"principal:global:{p.PrincipalId}";
		}

		private static string GetDotPrincipalNodeId(TboCacheDatabase.GraphPrincipalRow p)
		{
			if (string.Equals(p.Scope, "Machine", StringComparison.OrdinalIgnoreCase))
			{
				var machinePart = p.ScopeMachineId.HasValue
					? p.ScopeMachineId.Value.ToString(CultureInfo.InvariantCulture)
					: "0";
				return $"pm{machinePart}_{p.PrincipalId}";
			}

			return $"pg{p.PrincipalId}";
		}

	}

	[Cmdlet(VerbsData.Export, "TBOCacheJson")]
	[OutputType(typeof(string))]
	public sealed class ExportTBOCacheJson : PSCmdlet
	{
		[Parameter]
		public string? Path { get; set; }

		protected override void ProcessRecord()
		{
			using var db = TboCacheDatabase.Open(this.Path, msg => this.WriteVerbose(msg));
			var (schemaVersion, resolvedPath) = db.GetInfo(this.Path);
			var graph = db.QueryGraphData();
			var dpapiMasterKeys = db.QueryDpapiMasterKeys();
			var dpapiBlobs = db.QueryDpapiBlobs();
			var writeActivities = db.QueryWriteActivities();

			using var ms = new MemoryStream();
			using (var writer = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true }))
			{
				writer.WriteStartObject();

				writer.WriteString("schema", "tbo.cache.export.v1");
				writer.WriteString("exportedUtc", DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture));
				writer.WriteNumber("schemaVersion", schemaVersion);
				writer.WriteString("cachePath", resolvedPath);

				writer.WriteStartArray("machines");
				foreach (var m in graph.Machines)
				{
					writer.WriteStartObject();
					writer.WriteNumber("machineId", m.MachineId);
					writer.WriteString("serverName", m.ServerName);
					writer.WriteString("firstSeenUtc", m.FirstSeenUtc);
					writer.WriteString("lastSeenUtc", m.LastSeenUtc);
					writer.WriteEndObject();
				}
				writer.WriteEndArray();

				writer.WriteStartArray("principals");
				foreach (var p in graph.Principals)
				{
					writer.WriteStartObject();
					writer.WriteNumber("principalId", p.PrincipalId);
					writer.WriteString("scope", p.Scope);
					if (p.ScopeMachineId.HasValue)
						writer.WriteNumber("scopeMachineId", p.ScopeMachineId.Value);
					if (!string.IsNullOrWhiteSpace(p.Sid))
						writer.WriteString("sid", p.Sid);
					if (!string.IsNullOrWhiteSpace(p.Domain))
						writer.WriteString("domain", p.Domain);
					if (!string.IsNullOrWhiteSpace(p.Name))
						writer.WriteString("name", p.Name);
					if (!string.IsNullOrWhiteSpace(p.Type))
						writer.WriteString("principalType", p.Type);
					writer.WriteString("firstSeenUtc", p.FirstSeenUtc);
					writer.WriteString("lastSeenUtc", p.LastSeenUtc);
					writer.WriteEndObject();
				}
				writer.WriteEndArray();

				writer.WriteStartArray("credentials");
				foreach (var c in graph.Credentials)
				{
					writer.WriteStartObject();
					writer.WriteNumber("credentialId", c.CredentialId);
					writer.WriteString("kind", c.Kind);
					writer.WriteString("identifier", c.Identifier);
					writer.WriteString("firstSeenUtc", c.FirstSeenUtc);
					writer.WriteString("lastSeenUtc", c.LastSeenUtc);
					writer.WriteEndObject();
				}
				writer.WriteEndArray();

				writer.WriteStartArray("observations");
				foreach (var o in graph.Observations)
				{
					writer.WriteStartObject();
					writer.WriteNumber("observationId", o.ObservationId);
					writer.WriteNumber("machineId", o.MachineId);
					if (o.PrincipalId.HasValue)
						writer.WriteNumber("principalId", o.PrincipalId.Value);
					if (o.CredentialId.HasValue)
						writer.WriteNumber("credentialId", o.CredentialId.Value);
					writer.WriteString("sourceKind", o.SourceKind);
					if (!string.IsNullOrWhiteSpace(o.SourcePath))
						writer.WriteString("sourcePath", o.SourcePath);
					writer.WriteString("observedUtc", o.ObservedUtc);
					if (o.Confidence.HasValue)
						writer.WriteNumber("confidence", o.Confidence.Value);
					if (!string.IsNullOrWhiteSpace(o.ContextJson))
						writer.WriteString("contextJson", o.ContextJson);
					writer.WriteEndObject();
				}
				writer.WriteEndArray();

				writer.WriteStartArray("dpapiMasterKeys");
				foreach (var mk in dpapiMasterKeys)
				{
					writer.WriteStartObject();
					writer.WriteNumber("dpapiMasterKeyId", mk.DpapiMasterKeyId);
					writer.WriteNumber("machineId", mk.MachineId);
					writer.WriteString("scope", mk.Scope);
					if (!string.IsNullOrWhiteSpace(mk.UserSid))
						writer.WriteString("userSid", mk.UserSid);
					writer.WriteString("keyPath", mk.KeyPath);
					writer.WriteString("masterKeyGuid", mk.MasterKeyGuid);
					writer.WriteBoolean("isPreferred", mk.IsPreferred);
					if (mk.IsDomain.HasValue)
						writer.WriteBoolean("isDomain", mk.IsDomain.Value);
					if (mk.HashContext.HasValue)
						writer.WriteNumber("hashContext", mk.HashContext.Value);
					if (!string.IsNullOrWhiteSpace(mk.Hash))
						writer.WriteString("hash", mk.Hash);
					if (!string.IsNullOrWhiteSpace(mk.HashLine))
						writer.WriteString("hashLine", mk.HashLine);
					if (mk.CleartextKey != null && mk.CleartextKey.Length > 0)
						writer.WriteString("cleartextKey", Convert.ToHexString(mk.CleartextKey));
					if (!string.IsNullOrWhiteSpace(mk.CleartextKeySha1))
						writer.WriteString("cleartextKeySha1", mk.CleartextKeySha1);
					if (!string.IsNullOrWhiteSpace(mk.FailureReason))
						writer.WriteString("failureReason", mk.FailureReason);
					writer.WriteString("firstSeenUtc", mk.FirstSeenUtc);
					writer.WriteString("lastSeenUtc", mk.LastSeenUtc);
					writer.WriteEndObject();
				}
				writer.WriteEndArray();

				writer.WriteStartArray("dpapiBlobs");
				foreach (var b in dpapiBlobs)
				{
					writer.WriteStartObject();
					writer.WriteNumber("dpapiBlobId", b.DpapiBlobId);
					writer.WriteNumber("machineId", b.MachineId);
					writer.WriteString("blobKey", b.BlobKey);
					writer.WriteString("source", b.Source);
					writer.WriteString("path", b.Path);
					if (!string.IsNullOrWhiteSpace(b.ValueName))
						writer.WriteString("valueName", b.ValueName);
					if (b.ValueType.HasValue)
						writer.WriteNumber("valueType", b.ValueType.Value);
					if (b.DataLength.HasValue)
						writer.WriteNumber("dataLength", b.DataLength.Value);
					if (b.FileSize.HasValue)
						writer.WriteNumber("fileSize", b.FileSize.Value);
					writer.WriteNumber("matchOffset", b.MatchOffset);
					writer.WriteNumber("bytesScanned", b.BytesScanned);
					if (!string.IsNullOrWhiteSpace(b.CredentialGuid))
						writer.WriteString("credentialGuid", b.CredentialGuid);
					if (!string.IsNullOrWhiteSpace(b.MasterKeyGuid))
						writer.WriteString("masterKeyGuid", b.MasterKeyGuid);
					if (b.Flags.HasValue)
						writer.WriteNumber("flags", b.Flags.Value);
					if (!string.IsNullOrWhiteSpace(b.Description))
						writer.WriteString("description", b.Description);
					if (b.CryptAlgorithmId.HasValue)
						writer.WriteNumber("cryptAlgorithmId", b.CryptAlgorithmId.Value);
					if (b.HashAlgorithmId.HasValue)
						writer.WriteNumber("hashAlgorithmId", b.HashAlgorithmId.Value);
					if (!string.IsNullOrWhiteSpace(b.ParseFailureReason))
						writer.WriteString("parseFailureReason", b.ParseFailureReason);
					writer.WriteString("firstSeenUtc", b.FirstSeenUtc);
					writer.WriteString("lastSeenUtc", b.LastSeenUtc);
					writer.WriteEndObject();
				}
				writer.WriteEndArray();

				writer.WriteStartArray("writeActivities");
				foreach (var a in writeActivities)
				{
					writer.WriteStartObject();
					writer.WriteNumber("writeActivityId", a.WriteActivityId);
					writer.WriteNumber("machineId", a.MachineId);
					writer.WriteString("cmdlet", a.Cmdlet);
					writer.WriteString("kind", a.Kind);
					writer.WriteString("action", a.Action);
					writer.WriteString("target", a.Target);
					writer.WriteString("path", a.Path);
					if (!string.IsNullOrWhiteSpace(a.ValueName))
						writer.WriteString("valueName", a.ValueName);
					if (a.ValueType.HasValue)
						writer.WriteNumber("valueType", a.ValueType.Value);
					if (!string.IsNullOrWhiteSpace(a.BeforeBlobKind))
						writer.WriteString("beforeBlobKind", a.BeforeBlobKind);
					if (a.BeforeBlob != null)
						writer.WriteBase64String("beforeBlobBase64", a.BeforeBlob);
					if (!string.IsNullOrWhiteSpace(a.AfterBlobKind))
						writer.WriteString("afterBlobKind", a.AfterBlobKind);
					if (a.AfterBlob != null)
						writer.WriteBase64String("afterBlobBase64", a.AfterBlob);
					if (!string.IsNullOrWhiteSpace(a.ContextJson))
						writer.WriteString("contextJson", a.ContextJson);
					writer.WriteBoolean("success", a.Success);
					if (!string.IsNullOrWhiteSpace(a.FailureReason))
						writer.WriteString("failureReason", a.FailureReason);
					writer.WriteString("activityUtc", a.ActivityUtc);
					writer.WriteEndObject();
				}
				writer.WriteEndArray();

				writer.WriteEndObject();
			}

			this.WriteObject(Encoding.UTF8.GetString(ms.ToArray()));
		}
	}
}
