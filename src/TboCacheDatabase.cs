using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using Microsoft.Data.Sqlite;

namespace Titanis.Tbo.Smb2.PowerShell
{
	/// <summary>
	/// Small SQLite-backed cache for correlating principals/credentials across triage sessions.
	/// </summary>
	/// <remarks>
	/// This is intentionally minimal and internal. Cmdlets and other collectors should not execute SQL directly.
	/// </remarks>
	internal sealed class TboCacheDatabase : IDisposable
	{
		internal const string CachePathEnvVar = "TITANIS_TBO_CACHE";

		private const int SchemaVersion = 1;
		private readonly SqliteConnection _connection;

		private TboCacheDatabase(SqliteConnection connection)
		{
			_connection = connection ?? throw new ArgumentNullException(nameof(connection));
		}

		public void Dispose()
		{
			_connection.Dispose();
		}

		internal static string ResolveCachePath(string? explicitPath = null)
		{
			if (!string.IsNullOrWhiteSpace(explicitPath))
				return Path.GetFullPath(explicitPath);

			var env = Environment.GetEnvironmentVariable(CachePathEnvVar);
			if (!string.IsNullOrWhiteSpace(env))
			{
				// Allow "1/true/yes" to mean "use the default path".
				if (IsTruthy(env))
					return GetDefaultCachePath();

				return Path.GetFullPath(env);
			}

			return GetDefaultCachePath();
		}

		internal static bool IsTruthy(string value)
		{
			if (string.IsNullOrWhiteSpace(value))
				return false;

			return value.Trim() switch
			{
				"1" => true,
				"true" => true,
				"True" => true,
				"TRUE" => true,
				"yes" => true,
				"Yes" => true,
				"YES" => true,
				_ => false
			};
		}

		private static string GetDefaultCachePath()
		{
			var baseDir = OperatingSystem.IsWindows()
				? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
				: Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

			if (string.IsNullOrWhiteSpace(baseDir))
				throw new InvalidOperationException("Could not resolve a default cache directory for the current user.");

			var dir = OperatingSystem.IsWindows()
				? Path.Combine(baseDir, "TBO")
				: Path.Combine(baseDir, ".tbo");

			return Path.Combine(dir, "cache.sqlite3");
		}

		internal static TboCacheDatabase Open(string? explicitPath = null, Action<string>? logDiagnostic = null)
		{
			logDiagnostic ??= _ => { };

			SqliteBootstrap.EnsureInitialized(logDiagnostic);

			var path = ResolveCachePath(explicitPath);
			var parent = Path.GetDirectoryName(path);
			if (string.IsNullOrWhiteSpace(parent))
				throw new ArgumentException("Cache path must include a parent directory.", nameof(explicitPath));

			Directory.CreateDirectory(parent);

			var builder = new SqliteConnectionStringBuilder
			{
				DataSource = path,
				Mode = SqliteOpenMode.ReadWriteCreate,
				Cache = SqliteCacheMode.Shared,
				// Keep cache cmdlets "one-shot". Pooling can keep the file handle open (breaking test cleanup
				// and surprising users who want to move/delete the cache).
				Pooling = false
			};

			var conn = new SqliteConnection(builder.ToString());
			conn.Open();

			var db = new TboCacheDatabase(conn);
			db.Initialize(logDiagnostic);
			return db;
		}

		private void Initialize(Action<string> logDiagnostic)
		{
			// Keep initialization idempotent. WAL mode improves multi-session behavior.
			using (var cmd = _connection.CreateCommand())
			{
				cmd.CommandText =
					"PRAGMA foreign_keys=ON;" +
					"PRAGMA journal_mode=WAL;" +
					"PRAGMA synchronous=NORMAL;" +
					"PRAGMA busy_timeout=5000;";
				cmd.ExecuteNonQuery();
			}

			var userVersion = GetUserVersion();
			if (userVersion == 0)
			{
				logDiagnostic($"TBO cache: initializing new DB (schema v{SchemaVersion}).");
				ApplySchemaV1();
				SetUserVersion(SchemaVersion);
				return;
			}

			if (userVersion > SchemaVersion)
			{
				throw new NotSupportedException(
					$"Cache DB schema version {userVersion} is newer than this build supports (max {SchemaVersion}).");
			}

			// Future: apply migrations here.
		}

		private int GetUserVersion()
		{
			using var cmd = _connection.CreateCommand();
			cmd.CommandText = "PRAGMA user_version;";
			var value = cmd.ExecuteScalar();
			return value is long l ? unchecked((int)l) : 0;
		}

		private void SetUserVersion(int version)
		{
			using var cmd = _connection.CreateCommand();
			cmd.CommandText = $"PRAGMA user_version={version};";
			cmd.ExecuteNonQuery();
		}

		private void ApplySchemaV1()
		{
			using var tx = _connection.BeginTransaction();

			Exec(@"
CREATE TABLE IF NOT EXISTS machines(
  machine_id INTEGER PRIMARY KEY,
  server_name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  first_seen_utc TEXT NOT NULL,
  last_seen_utc TEXT NOT NULL
);
", tx);

			Exec(@"
CREATE TABLE IF NOT EXISTS principals(
  principal_id INTEGER PRIMARY KEY,
  sid TEXT NULL UNIQUE COLLATE NOCASE,
  domain TEXT NULL,
  name TEXT NULL,
  type TEXT NULL,
  first_seen_utc TEXT NOT NULL,
  last_seen_utc TEXT NOT NULL
);
", tx);

			Exec(@"
CREATE TABLE IF NOT EXISTS credentials(
  credential_id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL,
  identifier TEXT NOT NULL,
  secret_blob BLOB NULL,
  first_seen_utc TEXT NOT NULL,
  last_seen_utc TEXT NOT NULL,
  UNIQUE(kind, identifier)
);
", tx);

			Exec(@"
CREATE TABLE IF NOT EXISTS observations(
  observation_id INTEGER PRIMARY KEY,
  machine_id INTEGER NOT NULL REFERENCES machines(machine_id),
  principal_id INTEGER NULL REFERENCES principals(principal_id),
  credential_id INTEGER NULL REFERENCES credentials(credential_id),
  source_kind TEXT NOT NULL,
  source_path TEXT NULL,
  observed_utc TEXT NOT NULL,
  context_json TEXT NULL,
  confidence INTEGER NULL
);
", tx);

			Exec("CREATE INDEX IF NOT EXISTS idx_observations_machine_id ON observations(machine_id);", tx);
			Exec("CREATE INDEX IF NOT EXISTS idx_observations_principal_id ON observations(principal_id);", tx);
			Exec("CREATE INDEX IF NOT EXISTS idx_observations_credential_id ON observations(credential_id);", tx);
			Exec("CREATE INDEX IF NOT EXISTS idx_credentials_kind_identifier ON credentials(kind, identifier);", tx);

			tx.Commit();
		}

		private void Exec(string sql, SqliteTransaction tx)
		{
			using var cmd = _connection.CreateCommand();
			cmd.Transaction = tx;
			cmd.CommandText = sql;
			cmd.ExecuteNonQuery();
		}

		private static string UtcNowIso8601()
			=> DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture);

		internal long UpsertMachine(string serverName)
		{
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("ServerName must be provided.", nameof(serverName));

			var now = UtcNowIso8601();

			using (var cmd = _connection.CreateCommand())
			{
				cmd.CommandText = @"
INSERT INTO machines(server_name, first_seen_utc, last_seen_utc)
VALUES ($server_name, $now, $now)
ON CONFLICT(server_name) DO UPDATE SET last_seen_utc=$now
RETURNING machine_id;";
				cmd.Parameters.AddWithValue("$server_name", serverName);
				cmd.Parameters.AddWithValue("$now", now);

				var result = cmd.ExecuteScalar();
				return (long)result!;
			}
		}

		internal long UpsertPrincipal(string? sid, string? domain, string? name, string? type)
		{
			var now = UtcNowIso8601();

			// Prefer SID-based identity when available.
			if (!string.IsNullOrWhiteSpace(sid))
			{
				using var cmd = _connection.CreateCommand();
				cmd.CommandText = @"
INSERT INTO principals(sid, domain, name, type, first_seen_utc, last_seen_utc)
VALUES ($sid, $domain, $name, $type, $now, $now)
ON CONFLICT(sid) DO UPDATE SET
  domain=COALESCE(excluded.domain, domain),
  name=COALESCE(excluded.name, name),
  type=COALESCE(excluded.type, type),
  last_seen_utc=$now
RETURNING principal_id;";

				cmd.Parameters.AddWithValue("$sid", sid);
				cmd.Parameters.AddWithValue("$domain", (object?)domain ?? DBNull.Value);
				cmd.Parameters.AddWithValue("$name", (object?)name ?? DBNull.Value);
				cmd.Parameters.AddWithValue("$type", (object?)type ?? DBNull.Value);
				cmd.Parameters.AddWithValue("$now", now);
				return (long)cmd.ExecuteScalar()!;
			}

			// Best-effort de-dupe for principals without a SID.
			//
			// Rationale:
			// - SID is the safest identifier, but we don't always have it (for example: SAM hashing by account name).
			// - Dedupe by RID alone is not safe (local Administrator is commonly RID 500).
			// - Dedupe by name alone is not safe without a namespace/domain (collisions across machines).
			//
			// Strategy:
			// - If domain+name are present, reuse an existing SID-less principal for (domain,name,type), allowing type upgrades.
			// - Otherwise, insert a new row. Callers can later merge by SID if discovered.
			if (!string.IsNullOrWhiteSpace(domain) && !string.IsNullOrWhiteSpace(name))
			{
				long? existingId = null;
				using (var select = _connection.CreateCommand())
				{
					select.CommandText = @"
SELECT principal_id
FROM principals
WHERE sid IS NULL
  AND domain = $domain COLLATE NOCASE
  AND name = $name COLLATE NOCASE
  AND (
    ($type IS NOT NULL AND (type IS NULL OR type = $type COLLATE NOCASE))
    OR ($type IS NULL AND type IS NULL)
  )
ORDER BY principal_id
LIMIT 1;";

					select.Parameters.AddWithValue("$domain", domain);
					select.Parameters.AddWithValue("$name", name);
					select.Parameters.AddWithValue("$type", (object?)type ?? DBNull.Value);

					var result = select.ExecuteScalar();
					if (result != null && result != DBNull.Value)
						existingId = (long)result;
				}

				if (existingId.HasValue)
				{
					using var update = _connection.CreateCommand();
					update.CommandText = @"
UPDATE principals
SET
  type=COALESCE($type, type),
  last_seen_utc=$now
WHERE principal_id=$principal_id;";
					update.Parameters.AddWithValue("$principal_id", existingId.Value);
					update.Parameters.AddWithValue("$type", (object?)type ?? DBNull.Value);
					update.Parameters.AddWithValue("$now", now);
					update.ExecuteNonQuery();
					return existingId.Value;
				}
			}

			// If SID is unknown (or the best-effort dedupe key was not usable), create a new principal record.
			using (var insert = _connection.CreateCommand())
			{
				insert.CommandText = @"
INSERT INTO principals(sid, domain, name, type, first_seen_utc, last_seen_utc)
VALUES (NULL, $domain, $name, $type, $now, $now)
RETURNING principal_id;";
				insert.Parameters.AddWithValue("$domain", (object?)domain ?? DBNull.Value);
				insert.Parameters.AddWithValue("$name", (object?)name ?? DBNull.Value);
				insert.Parameters.AddWithValue("$type", (object?)type ?? DBNull.Value);
				insert.Parameters.AddWithValue("$now", now);
				return (long)insert.ExecuteScalar()!;
			}
		}

		internal long UpsertCredential(string kind, string identifier, byte[]? secretBlob = null)
		{
			if (string.IsNullOrWhiteSpace(kind))
				throw new ArgumentException("Credential kind must be provided.", nameof(kind));
			if (string.IsNullOrWhiteSpace(identifier))
				throw new ArgumentException("Credential identifier must be provided.", nameof(identifier));

			var now = UtcNowIso8601();

			using var cmd = _connection.CreateCommand();
			cmd.CommandText = @"
INSERT INTO credentials(kind, identifier, secret_blob, first_seen_utc, last_seen_utc)
VALUES ($kind, $identifier, $secret_blob, $now, $now)
ON CONFLICT(kind, identifier) DO UPDATE SET
  last_seen_utc=$now
RETURNING credential_id;";

			cmd.Parameters.AddWithValue("$kind", kind);
			cmd.Parameters.AddWithValue("$identifier", identifier);
			cmd.Parameters.AddWithValue("$secret_blob", (object?)secretBlob ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$now", now);

			return (long)cmd.ExecuteScalar()!;
		}

		internal long InsertObservation(
			long machineId,
			long? principalId,
			long? credentialId,
			string sourceKind,
			string? sourcePath,
			DateTime? observedUtc = null,
			string? contextJson = null,
			int? confidence = null)
		{
			if (machineId <= 0)
				throw new ArgumentOutOfRangeException(nameof(machineId));
			if (string.IsNullOrWhiteSpace(sourceKind))
				throw new ArgumentException("Source kind must be provided.", nameof(sourceKind));

			var observed = (observedUtc ?? DateTime.UtcNow).ToString("O", CultureInfo.InvariantCulture);

			using var cmd = _connection.CreateCommand();
			cmd.CommandText = @"
INSERT INTO observations(machine_id, principal_id, credential_id, source_kind, source_path, observed_utc, context_json, confidence)
VALUES ($machine_id, $principal_id, $credential_id, $source_kind, $source_path, $observed_utc, $context_json, $confidence)
RETURNING observation_id;";

			cmd.Parameters.AddWithValue("$machine_id", machineId);
			cmd.Parameters.AddWithValue("$principal_id", (object?)principalId ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$credential_id", (object?)credentialId ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$source_kind", sourceKind);
			cmd.Parameters.AddWithValue("$source_path", (object?)sourcePath ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$observed_utc", observed);
			cmd.Parameters.AddWithValue("$context_json", (object?)contextJson ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$confidence", (object?)confidence ?? DBNull.Value);

			return (long)cmd.ExecuteScalar()!;
		}

		internal sealed class CredentialReuseRow
		{
			internal long CredentialId { get; init; }
			internal string Kind { get; init; } = "";
			internal string Identifier { get; init; } = "";
			internal long MachineCount { get; init; }

			internal string ServerName { get; init; } = "";
			internal string? PrincipalSid { get; init; }
			internal string? PrincipalDomain { get; init; }
			internal string? PrincipalName { get; init; }
			internal string? PrincipalType { get; init; }

			internal long ObservationCount { get; init; }
			internal string FirstObservedUtc { get; init; } = "";
			internal string LastObservedUtc { get; init; } = "";
		}

		internal IReadOnlyList<CredentialReuseRow> QueryCredentialReuse(
			string? kind,
			string? identifier,
			int minimumMachineCount)
		{
			if (minimumMachineCount < 2)
				throw new ArgumentOutOfRangeException(nameof(minimumMachineCount), "Minimum machine count must be >= 2.");

			kind = string.IsNullOrWhiteSpace(kind) ? null : kind.Trim();
			identifier = string.IsNullOrWhiteSpace(identifier) ? null : identifier.Trim();

			using var cmd = _connection.CreateCommand();
			cmd.CommandText = @"
WITH reused AS (
  SELECT
    c.credential_id AS credential_id,
    c.kind AS kind,
    c.identifier AS identifier,
    COUNT(DISTINCT o.machine_id) AS machine_count
  FROM credentials c
  JOIN observations o ON o.credential_id = c.credential_id
  WHERE ($kind IS NULL OR c.kind = $kind COLLATE NOCASE)
    AND ($identifier IS NULL OR c.identifier = $identifier COLLATE NOCASE)
  GROUP BY c.credential_id, c.kind, c.identifier
  HAVING machine_count >= $min_machine_count
)
SELECT
  reused.credential_id,
  reused.kind,
  reused.identifier,
  reused.machine_count,
  m.server_name,
  p.sid,
  p.domain,
  p.name,
  p.type,
  COUNT(1) AS observation_count,
  MIN(o.observed_utc) AS first_observed_utc,
  MAX(o.observed_utc) AS last_observed_utc
FROM reused
JOIN observations o ON o.credential_id = reused.credential_id
JOIN machines m ON m.machine_id = o.machine_id
LEFT JOIN principals p ON p.principal_id = o.principal_id
GROUP BY
  reused.credential_id,
  reused.kind,
  reused.identifier,
  reused.machine_count,
  m.server_name,
  p.sid,
  p.domain,
  p.name,
  p.type
ORDER BY
  reused.machine_count DESC,
  reused.kind,
  reused.identifier,
  m.server_name,
  p.domain,
  p.name;";

			cmd.Parameters.AddWithValue("$kind", (object?)kind ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$identifier", (object?)identifier ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$min_machine_count", minimumMachineCount);

			using var reader = cmd.ExecuteReader();
			var results = new List<CredentialReuseRow>();

			while (reader.Read())
			{
				results.Add(new CredentialReuseRow
				{
					CredentialId = reader.GetInt64(0),
					Kind = reader.GetString(1),
					Identifier = reader.GetString(2),
					MachineCount = reader.GetInt64(3),

					ServerName = reader.GetString(4),
					PrincipalSid = reader.IsDBNull(5) ? null : reader.GetString(5),
					PrincipalDomain = reader.IsDBNull(6) ? null : reader.GetString(6),
					PrincipalName = reader.IsDBNull(7) ? null : reader.GetString(7),
					PrincipalType = reader.IsDBNull(8) ? null : reader.GetString(8),

					ObservationCount = reader.GetInt64(9),
					FirstObservedUtc = reader.GetString(10),
					LastObservedUtc = reader.GetString(11),
				});
			}

			return results;
		}

		internal sealed class GraphMachineRow
		{
			internal long MachineId { get; init; }
			internal string ServerName { get; init; } = "";
			internal string FirstSeenUtc { get; init; } = "";
			internal string LastSeenUtc { get; init; } = "";
		}

		internal sealed class GraphPrincipalRow
		{
			internal long PrincipalId { get; init; }
			internal string? Sid { get; init; }
			internal string? Domain { get; init; }
			internal string? Name { get; init; }
			internal string? Type { get; init; }
			internal string FirstSeenUtc { get; init; } = "";
			internal string LastSeenUtc { get; init; } = "";
		}

		internal sealed class GraphCredentialRow
		{
			internal long CredentialId { get; init; }
			internal string Kind { get; init; } = "";
			internal string Identifier { get; init; } = "";
			internal string FirstSeenUtc { get; init; } = "";
			internal string LastSeenUtc { get; init; } = "";
		}

		internal sealed class GraphObservationRow
		{
			internal long ObservationId { get; init; }
			internal long MachineId { get; init; }
			internal long? PrincipalId { get; init; }
			internal long? CredentialId { get; init; }
			internal string SourceKind { get; init; } = "";
			internal string? SourcePath { get; init; }
			internal string ObservedUtc { get; init; } = "";
			internal string? ContextJson { get; init; }
			internal int? Confidence { get; init; }
		}

		internal sealed class GraphData
		{
			internal IReadOnlyList<GraphMachineRow> Machines { get; init; } = Array.Empty<GraphMachineRow>();
			internal IReadOnlyList<GraphPrincipalRow> Principals { get; init; } = Array.Empty<GraphPrincipalRow>();
			internal IReadOnlyList<GraphCredentialRow> Credentials { get; init; } = Array.Empty<GraphCredentialRow>();
			internal IReadOnlyList<GraphObservationRow> Observations { get; init; } = Array.Empty<GraphObservationRow>();
		}

		internal GraphData QueryGraphData()
		{
			return new GraphData
			{
				Machines = QueryGraphMachines(),
				Principals = QueryGraphPrincipals(),
				Credentials = QueryGraphCredentials(),
				Observations = QueryGraphObservations(),
			};
		}

		private IReadOnlyList<GraphMachineRow> QueryGraphMachines()
		{
			using var cmd = _connection.CreateCommand();
			cmd.CommandText = @"
SELECT machine_id, server_name, first_seen_utc, last_seen_utc
FROM machines
ORDER BY machine_id;";

			using var reader = cmd.ExecuteReader();
			var results = new List<GraphMachineRow>();
			while (reader.Read())
			{
				results.Add(new GraphMachineRow
				{
					MachineId = reader.GetInt64(0),
					ServerName = reader.GetString(1),
					FirstSeenUtc = reader.GetString(2),
					LastSeenUtc = reader.GetString(3),
				});
			}

			return results;
		}

		private IReadOnlyList<GraphPrincipalRow> QueryGraphPrincipals()
		{
			using var cmd = _connection.CreateCommand();
			cmd.CommandText = @"
SELECT principal_id, sid, domain, name, type, first_seen_utc, last_seen_utc
FROM principals
ORDER BY principal_id;";

			using var reader = cmd.ExecuteReader();
			var results = new List<GraphPrincipalRow>();
			while (reader.Read())
			{
				results.Add(new GraphPrincipalRow
				{
					PrincipalId = reader.GetInt64(0),
					Sid = reader.IsDBNull(1) ? null : reader.GetString(1),
					Domain = reader.IsDBNull(2) ? null : reader.GetString(2),
					Name = reader.IsDBNull(3) ? null : reader.GetString(3),
					Type = reader.IsDBNull(4) ? null : reader.GetString(4),
					FirstSeenUtc = reader.GetString(5),
					LastSeenUtc = reader.GetString(6),
				});
			}

			return results;
		}

		private IReadOnlyList<GraphCredentialRow> QueryGraphCredentials()
		{
			using var cmd = _connection.CreateCommand();
			cmd.CommandText = @"
SELECT credential_id, kind, identifier, first_seen_utc, last_seen_utc
FROM credentials
ORDER BY credential_id;";

			using var reader = cmd.ExecuteReader();
			var results = new List<GraphCredentialRow>();
			while (reader.Read())
			{
				results.Add(new GraphCredentialRow
				{
					CredentialId = reader.GetInt64(0),
					Kind = reader.GetString(1),
					Identifier = reader.GetString(2),
					FirstSeenUtc = reader.GetString(3),
					LastSeenUtc = reader.GetString(4),
				});
			}

			return results;
		}

		private IReadOnlyList<GraphObservationRow> QueryGraphObservations()
		{
			using var cmd = _connection.CreateCommand();
			cmd.CommandText = @"
SELECT observation_id, machine_id, principal_id, credential_id, source_kind, source_path, observed_utc, context_json, confidence
FROM observations
ORDER BY observation_id;";

			using var reader = cmd.ExecuteReader();
			var results = new List<GraphObservationRow>();
			while (reader.Read())
			{
				results.Add(new GraphObservationRow
				{
					ObservationId = reader.GetInt64(0),
					MachineId = reader.GetInt64(1),
					PrincipalId = reader.IsDBNull(2) ? null : reader.GetInt64(2),
					CredentialId = reader.IsDBNull(3) ? null : reader.GetInt64(3),
					SourceKind = reader.GetString(4),
					SourcePath = reader.IsDBNull(5) ? null : reader.GetString(5),
					ObservedUtc = reader.GetString(6),
					ContextJson = reader.IsDBNull(7) ? null : reader.GetString(7),
					Confidence = reader.IsDBNull(8) ? null : reader.GetInt32(8),
				});
			}

			return results;
		}

		internal IReadOnlyDictionary<string, long> GetCountsByTable()
		{
			var tables = new[]
			{
				"machines",
				"principals",
				"credentials",
				"observations"
			};

			var counts = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
			foreach (var table in tables)
			{
				using var cmd = _connection.CreateCommand();
				cmd.CommandText = $"SELECT COUNT(1) FROM {table};";
				var result = cmd.ExecuteScalar();
				counts[table] = result is long l ? l : 0;
			}

			return counts;
		}

		internal void ClearAll()
		{
			using var tx = _connection.BeginTransaction();
			using var cmd = _connection.CreateCommand();
			cmd.Transaction = tx;

			// Delete edges first to satisfy FK constraints.
			cmd.CommandText =
				"DELETE FROM observations;" +
				"DELETE FROM credentials;" +
				"DELETE FROM principals;" +
				"DELETE FROM machines;";
			cmd.ExecuteNonQuery();

			tx.Commit();
		}

		internal void RemoveEntries(TboCacheEntryType type, IReadOnlyCollection<long> ids)
		{
			if (ids == null)
				throw new ArgumentNullException(nameof(ids));

			if (ids.Count == 0)
				return;

			using var tx = _connection.BeginTransaction();
			using var cmd = _connection.CreateCommand();
			cmd.Transaction = tx;

			var inClause = AddLongParameters(cmd, "$id", ids);

			switch (type)
			{
				case TboCacheEntryType.Observation:
					cmd.CommandText = $"DELETE FROM observations WHERE observation_id IN ({inClause});";
					cmd.ExecuteNonQuery();
					break;

				case TboCacheEntryType.Machine:
					cmd.CommandText = $"DELETE FROM observations WHERE machine_id IN ({inClause});";
					cmd.ExecuteNonQuery();
					cmd.CommandText = $"DELETE FROM machines WHERE machine_id IN ({inClause});";
					cmd.ExecuteNonQuery();
					break;

				case TboCacheEntryType.Principal:
					cmd.CommandText = $"DELETE FROM observations WHERE principal_id IN ({inClause});";
					cmd.ExecuteNonQuery();
					cmd.CommandText = $"DELETE FROM principals WHERE principal_id IN ({inClause});";
					cmd.ExecuteNonQuery();
					break;

				case TboCacheEntryType.Credential:
					cmd.CommandText = $"DELETE FROM observations WHERE credential_id IN ({inClause});";
					cmd.ExecuteNonQuery();
					cmd.CommandText = $"DELETE FROM credentials WHERE credential_id IN ({inClause});";
					cmd.ExecuteNonQuery();
					break;

				default:
					throw new ArgumentOutOfRangeException(nameof(type), type, "Not a valid cache entry type.");
			}

			tx.Commit();
		}

		private static string AddLongParameters(SqliteCommand cmd, string baseName, IReadOnlyCollection<long> values)
		{
			var names = new List<string>(values.Count);
			int i = 0;
			foreach (var value in values)
			{
				var name = $"{baseName}{i++}";
				cmd.Parameters.AddWithValue(name, value);
				names.Add(name);
			}

			return string.Join(", ", names);
		}

		internal (int schemaVersion, string path) GetInfo(string? explicitPath = null)
		{
			// The DB path is not directly exposed by Microsoft.Data.Sqlite in a structured way;
			// track it at call sites using ResolveCachePath.
			return (GetUserVersion(), ResolveCachePath(explicitPath));
		}
	}
}
