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

		private static bool IsTruthy(string value)
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

			var path = ResolveCachePath(explicitPath);
			var parent = Path.GetDirectoryName(path);
			if (string.IsNullOrWhiteSpace(parent))
				throw new ArgumentException("Cache path must include a parent directory.", nameof(explicitPath));

			Directory.CreateDirectory(parent);

			var builder = new SqliteConnectionStringBuilder
			{
				DataSource = path,
				Mode = SqliteOpenMode.ReadWriteCreate,
				Cache = SqliteCacheMode.Shared
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

			// If SID is unknown, create a new principal record. Callers can later merge by SID if discovered.
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

		internal (int schemaVersion, string path) GetInfo(string? explicitPath = null)
		{
			// The DB path is not directly exposed by Microsoft.Data.Sqlite in a structured way;
			// track it at call sites using ResolveCachePath.
			return (GetUserVersion(), ResolveCachePath(explicitPath));
		}
	}
}
