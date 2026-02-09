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

		private const int SchemaVersion = 4;
		private readonly SqliteConnection _connection;

		internal enum PrincipalScope
		{
			Global = 1,
			Machine = 2
		}

		private const string PrincipalScopeGlobal = "Global";
		private const string PrincipalScopeMachine = "Machine";

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
				ApplySchemaV4();
				SetUserVersion(SchemaVersion);
				return;
			}

			if (userVersion > SchemaVersion)
			{
				throw new NotSupportedException(
					$"Cache DB schema version {userVersion} is newer than this build supports (max {SchemaVersion}).");
			}

			if (userVersion == 1)
			{
				logDiagnostic("TBO cache: migrating DB schema v1 -> v2.");
				MigrateSchemaV1ToV2(logDiagnostic);
				SetUserVersion(2);
				userVersion = 2;
			}

			if (userVersion == 2)
			{
				logDiagnostic("TBO cache: migrating DB schema v2 -> v3.");
				MigrateSchemaV2ToV3(logDiagnostic);
				SetUserVersion(3);
				userVersion = 3;
			}

			if (userVersion == 3)
			{
				logDiagnostic("TBO cache: migrating DB schema v3 -> v4.");
				MigrateSchemaV3ToV4(logDiagnostic);
				SetUserVersion(SchemaVersion);
				return;
			}

			// Schema is current.
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

		private void ApplySchemaV4()
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
  scope TEXT NOT NULL DEFAULT 'Global',
  scope_machine_id INTEGER NULL REFERENCES machines(machine_id) ON DELETE CASCADE,
  sid TEXT NULL COLLATE NOCASE,
  domain TEXT NULL,
  name TEXT NULL,
  type TEXT NULL,
  first_seen_utc TEXT NOT NULL,
  last_seen_utc TEXT NOT NULL
);
", tx);

			// Principals uniqueness rules (v2):
			// - Global principals: unique by SID when SID is present.
			// - Machine-scoped principals: unique by (machine_id,SID) when SID is present.
			//
			// Note: we intentionally avoid a single UNIQUE(scope, scope_machine_id, sid) index because
			// SQLite UNIQUE indexes treat NULL values as distinct (breaking global uniqueness where scope_machine_id is NULL).
			Exec(@"
CREATE UNIQUE INDEX IF NOT EXISTS uidx_principals_global_sid
ON principals(sid)
WHERE scope = 'Global' AND sid IS NOT NULL;
", tx);

			Exec(@"
CREATE UNIQUE INDEX IF NOT EXISTS uidx_principals_machine_sid
ON principals(scope_machine_id, sid)
WHERE scope = 'Machine' AND scope_machine_id IS NOT NULL AND sid IS NOT NULL;
", tx);

			// Non-unique helper indexes for best-effort SID-less lookups.
			Exec(@"
CREATE INDEX IF NOT EXISTS idx_principals_global_domain_name_type
ON principals(domain, name, type)
WHERE scope = 'Global' AND sid IS NULL AND domain IS NOT NULL AND name IS NOT NULL;
", tx);

			Exec(@"
CREATE INDEX IF NOT EXISTS idx_principals_machine_domain_name_type
ON principals(scope_machine_id, domain, name, type)
WHERE scope = 'Machine' AND sid IS NULL AND scope_machine_id IS NOT NULL AND domain IS NOT NULL AND name IS NOT NULL;
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

			Exec(@"
CREATE TABLE IF NOT EXISTS dpapi_masterkeys(
  dpapi_masterkey_id INTEGER PRIMARY KEY,
  machine_id INTEGER NOT NULL REFERENCES machines(machine_id) ON DELETE CASCADE,
  scope TEXT NOT NULL,
  user_sid TEXT NULL COLLATE NOCASE,
  key_path TEXT NOT NULL,
  master_key_guid TEXT NOT NULL COLLATE NOCASE,
  is_preferred INTEGER NOT NULL,
  is_domain INTEGER NULL,
  hash_context INTEGER NULL,
  hash TEXT NULL,
  hash_line TEXT NULL,
  failure_reason TEXT NULL,
  first_seen_utc TEXT NOT NULL,
  last_seen_utc TEXT NOT NULL,
  UNIQUE(machine_id, master_key_guid)
);
", tx);

			Exec("CREATE INDEX IF NOT EXISTS idx_dpapi_masterkeys_machine_id ON dpapi_masterkeys(machine_id);", tx);
			Exec("CREATE INDEX IF NOT EXISTS idx_dpapi_masterkeys_master_key_guid ON dpapi_masterkeys(master_key_guid);", tx);

			Exec(@"
CREATE TABLE IF NOT EXISTS dpapi_blobs(
  dpapi_blob_id INTEGER PRIMARY KEY,
  machine_id INTEGER NOT NULL REFERENCES machines(machine_id) ON DELETE CASCADE,
  blob_key TEXT NOT NULL,
  source TEXT NOT NULL,
  path TEXT NOT NULL,
  value_name TEXT NOT NULL DEFAULT '',
  value_type INTEGER NULL,
  data_length INTEGER NULL,
  file_size INTEGER NULL,
  match_offset INTEGER NOT NULL,
  bytes_scanned INTEGER NOT NULL,
  credential_guid TEXT NULL COLLATE NOCASE,
  master_key_guid TEXT NULL COLLATE NOCASE,
  flags INTEGER NULL,
  description TEXT NULL,
  crypt_algorithm_id INTEGER NULL,
  hash_algorithm_id INTEGER NULL,
  parse_failure_reason TEXT NULL,
  first_seen_utc TEXT NOT NULL,
  last_seen_utc TEXT NOT NULL,
  UNIQUE(machine_id, blob_key)
);
", tx);

			Exec("CREATE INDEX IF NOT EXISTS idx_dpapi_blobs_machine_id ON dpapi_blobs(machine_id);", tx);
			Exec("CREATE INDEX IF NOT EXISTS idx_dpapi_blobs_master_key_guid ON dpapi_blobs(master_key_guid);", tx);
			Exec("CREATE INDEX IF NOT EXISTS idx_dpapi_blobs_blob_key ON dpapi_blobs(blob_key);", tx);

			Exec(@"
CREATE TABLE IF NOT EXISTS write_activities(
  write_activity_id INTEGER PRIMARY KEY,
  machine_id INTEGER NOT NULL REFERENCES machines(machine_id) ON DELETE CASCADE,
  cmdlet TEXT NOT NULL,
  kind TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  path TEXT NOT NULL,
  value_name TEXT NOT NULL DEFAULT '',
  value_type INTEGER NULL,
  before_blob_kind TEXT NULL,
  before_blob BLOB NULL,
  after_blob_kind TEXT NULL,
  after_blob BLOB NULL,
  context_json TEXT NULL,
  success INTEGER NOT NULL,
  failure_reason TEXT NULL,
  activity_utc TEXT NOT NULL
);
", tx);

			Exec("CREATE INDEX IF NOT EXISTS idx_write_activities_machine_id ON write_activities(machine_id);", tx);
			Exec("CREATE INDEX IF NOT EXISTS idx_write_activities_activity_utc ON write_activities(activity_utc);", tx);

			tx.Commit();
		}

		private void MigrateSchemaV1ToV2(Action<string> logDiagnostic)
		{
			// Schema v1 had a UNIQUE constraint directly on principals.sid, which prevents representing machine-scoped
			// principals that share well-known/builtin SIDs across hosts (for example, SYSTEM and BUILTIN groups).
			//
			// Migration approach:
			// - Rebuild the principals table (SQLite cannot drop a column-level UNIQUE constraint).
			// - Preserve principal_id values so existing observations remain valid.
			// - Backfill existing principals as Global scope.
			//
			// Foreign keys must be disabled while dropping/replacing the referenced principals table.
			using (var fk = _connection.CreateCommand())
			{
				fk.CommandText = "PRAGMA foreign_keys=OFF;";
				fk.ExecuteNonQuery();
			}

			using var tx = _connection.BeginTransaction();

			Exec(@"
CREATE TABLE principals_v2(
  principal_id INTEGER PRIMARY KEY,
  scope TEXT NOT NULL DEFAULT 'Global',
  scope_machine_id INTEGER NULL REFERENCES machines(machine_id) ON DELETE CASCADE,
  sid TEXT NULL COLLATE NOCASE,
  domain TEXT NULL,
  name TEXT NULL,
  type TEXT NULL,
  first_seen_utc TEXT NOT NULL,
  last_seen_utc TEXT NOT NULL
);
", tx);

			Exec(@"
INSERT INTO principals_v2(principal_id, scope, scope_machine_id, sid, domain, name, type, first_seen_utc, last_seen_utc)
SELECT principal_id, 'Global', NULL, sid, domain, name, type, first_seen_utc, last_seen_utc
FROM principals;
", tx);

			Exec("DROP TABLE principals;", tx);
			Exec("ALTER TABLE principals_v2 RENAME TO principals;", tx);

			Exec(@"
CREATE UNIQUE INDEX uidx_principals_global_sid
ON principals(sid)
WHERE scope = 'Global' AND sid IS NOT NULL;
", tx);

			Exec(@"
CREATE UNIQUE INDEX uidx_principals_machine_sid
ON principals(scope_machine_id, sid)
WHERE scope = 'Machine' AND scope_machine_id IS NOT NULL AND sid IS NOT NULL;
", tx);

			Exec(@"
CREATE INDEX idx_principals_global_domain_name_type
ON principals(domain, name, type)
WHERE scope = 'Global' AND sid IS NULL AND domain IS NOT NULL AND name IS NOT NULL;
", tx);

			Exec(@"
CREATE INDEX idx_principals_machine_domain_name_type
ON principals(scope_machine_id, domain, name, type)
WHERE scope = 'Machine' AND sid IS NULL AND scope_machine_id IS NOT NULL AND domain IS NOT NULL AND name IS NOT NULL;
", tx);

			tx.Commit();

			using (var fk = _connection.CreateCommand())
			{
				fk.CommandText = "PRAGMA foreign_keys=ON;";
				fk.ExecuteNonQuery();
			}

			logDiagnostic("TBO cache: migration to schema v2 complete.");
		}

		private void MigrateSchemaV2ToV3(Action<string> logDiagnostic)
		{
			using var tx = _connection.BeginTransaction();

			Exec(@"
CREATE TABLE IF NOT EXISTS dpapi_masterkeys(
  dpapi_masterkey_id INTEGER PRIMARY KEY,
  machine_id INTEGER NOT NULL REFERENCES machines(machine_id) ON DELETE CASCADE,
  scope TEXT NOT NULL,
  user_sid TEXT NULL COLLATE NOCASE,
  key_path TEXT NOT NULL,
  master_key_guid TEXT NOT NULL COLLATE NOCASE,
  is_preferred INTEGER NOT NULL,
  is_domain INTEGER NULL,
  hash_context INTEGER NULL,
  hash TEXT NULL,
  hash_line TEXT NULL,
  failure_reason TEXT NULL,
  first_seen_utc TEXT NOT NULL,
  last_seen_utc TEXT NOT NULL,
  UNIQUE(machine_id, master_key_guid)
);
", tx);

			Exec("CREATE INDEX IF NOT EXISTS idx_dpapi_masterkeys_machine_id ON dpapi_masterkeys(machine_id);", tx);
			Exec("CREATE INDEX IF NOT EXISTS idx_dpapi_masterkeys_master_key_guid ON dpapi_masterkeys(master_key_guid);", tx);

			Exec(@"
CREATE TABLE IF NOT EXISTS dpapi_blobs(
  dpapi_blob_id INTEGER PRIMARY KEY,
  machine_id INTEGER NOT NULL REFERENCES machines(machine_id) ON DELETE CASCADE,
  blob_key TEXT NOT NULL,
  source TEXT NOT NULL,
  path TEXT NOT NULL,
  value_name TEXT NOT NULL DEFAULT '',
  value_type INTEGER NULL,
  data_length INTEGER NULL,
  file_size INTEGER NULL,
  match_offset INTEGER NOT NULL,
  bytes_scanned INTEGER NOT NULL,
  credential_guid TEXT NULL COLLATE NOCASE,
  master_key_guid TEXT NULL COLLATE NOCASE,
  flags INTEGER NULL,
  description TEXT NULL,
  crypt_algorithm_id INTEGER NULL,
  hash_algorithm_id INTEGER NULL,
  parse_failure_reason TEXT NULL,
  first_seen_utc TEXT NOT NULL,
  last_seen_utc TEXT NOT NULL,
  UNIQUE(machine_id, blob_key)
);
", tx);

			Exec("CREATE INDEX IF NOT EXISTS idx_dpapi_blobs_machine_id ON dpapi_blobs(machine_id);", tx);
			Exec("CREATE INDEX IF NOT EXISTS idx_dpapi_blobs_master_key_guid ON dpapi_blobs(master_key_guid);", tx);
			Exec("CREATE INDEX IF NOT EXISTS idx_dpapi_blobs_blob_key ON dpapi_blobs(blob_key);", tx);

			tx.Commit();

			logDiagnostic("TBO cache: migration to schema v3 complete.");
		}

		private void MigrateSchemaV3ToV4(Action<string> logDiagnostic)
		{
			using var tx = _connection.BeginTransaction();

			Exec(@"
CREATE TABLE IF NOT EXISTS write_activities(
  write_activity_id INTEGER PRIMARY KEY,
  machine_id INTEGER NOT NULL REFERENCES machines(machine_id) ON DELETE CASCADE,
  cmdlet TEXT NOT NULL,
  kind TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  path TEXT NOT NULL,
  value_name TEXT NOT NULL DEFAULT '',
  value_type INTEGER NULL,
  before_blob_kind TEXT NULL,
  before_blob BLOB NULL,
  after_blob_kind TEXT NULL,
  after_blob BLOB NULL,
  context_json TEXT NULL,
  success INTEGER NOT NULL,
  failure_reason TEXT NULL,
  activity_utc TEXT NOT NULL
);
", tx);

			Exec("CREATE INDEX IF NOT EXISTS idx_write_activities_machine_id ON write_activities(machine_id);", tx);
			Exec("CREATE INDEX IF NOT EXISTS idx_write_activities_activity_utc ON write_activities(activity_utc);", tx);

			tx.Commit();

			logDiagnostic("TBO cache: migration to schema v4 complete.");
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
			=> UpsertPrincipal(sid, domain, name, type, PrincipalScope.Global, scopeMachineId: null);

		internal long UpsertPrincipal(string? sid, string? domain, string? name, string? type, PrincipalScope scope, long? scopeMachineId)
		{
			var now = UtcNowIso8601();

			var scopeValue = scope == PrincipalScope.Machine
				? PrincipalScopeMachine
				: PrincipalScopeGlobal;

			long? machineId = null;
			if (scope == PrincipalScope.Machine)
			{
				if (!scopeMachineId.HasValue || scopeMachineId.Value <= 0)
					throw new ArgumentOutOfRangeException(nameof(scopeMachineId), scopeMachineId, "Machine-scoped principals require a valid scope machine id.");

				machineId = scopeMachineId.Value;
			}

			// Prefer SID-based identity when available.
			if (!string.IsNullOrWhiteSpace(sid))
			{
				using var cmd = _connection.CreateCommand();

				if (scope == PrincipalScope.Machine)
				{
					cmd.CommandText = @"
INSERT INTO principals(scope, scope_machine_id, sid, domain, name, type, first_seen_utc, last_seen_utc)
VALUES ('Machine', $scope_machine_id, $sid, $domain, $name, $type, $now, $now)
ON CONFLICT(scope_machine_id, sid) WHERE scope = 'Machine' AND sid IS NOT NULL DO UPDATE SET
  domain=COALESCE(excluded.domain, domain),
  name=COALESCE(excluded.name, name),
  type=COALESCE(excluded.type, type),
  last_seen_utc=$now
RETURNING principal_id;";
					cmd.Parameters.AddWithValue("$scope_machine_id", machineId!.Value);
				}
				else
				{
					cmd.CommandText = @"
INSERT INTO principals(scope, scope_machine_id, sid, domain, name, type, first_seen_utc, last_seen_utc)
VALUES ('Global', NULL, $sid, $domain, $name, $type, $now, $now)
ON CONFLICT(sid) WHERE scope = 'Global' AND sid IS NOT NULL DO UPDATE SET
  domain=COALESCE(excluded.domain, domain),
  name=COALESCE(excluded.name, name),
  type=COALESCE(excluded.type, type),
  last_seen_utc=$now
RETURNING principal_id;";
				}

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
			// - If domain+name are present, reuse an existing SID-less principal for (scope,domain,name,type), allowing type upgrades.
			// - Otherwise, insert a new row. Callers can later merge by SID if discovered.
			if (!string.IsNullOrWhiteSpace(domain) && !string.IsNullOrWhiteSpace(name))
			{
				var scopePredicate = scope == PrincipalScope.Machine
					? "scope = 'Machine' AND scope_machine_id = $scope_machine_id"
					: "scope = 'Global' AND scope_machine_id IS NULL";

				long? existingId = null;
				using (var select = _connection.CreateCommand())
				{
					select.CommandText = $@"
SELECT principal_id
FROM principals
WHERE sid IS NULL
  AND {scopePredicate}
  AND domain = $domain COLLATE NOCASE
  AND name = $name COLLATE NOCASE
  AND (
    ($type IS NOT NULL AND (type IS NULL OR type = $type COLLATE NOCASE))
    OR ($type IS NULL AND type IS NULL)
  )
ORDER BY principal_id
LIMIT 1;";

					select.Parameters.AddWithValue("$scope_machine_id", (object?)machineId ?? DBNull.Value);
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
INSERT INTO principals(scope, scope_machine_id, sid, domain, name, type, first_seen_utc, last_seen_utc)
VALUES ($scope, $scope_machine_id, NULL, $domain, $name, $type, $now, $now)
RETURNING principal_id;";
				insert.Parameters.AddWithValue("$scope", scopeValue);
				insert.Parameters.AddWithValue("$scope_machine_id", (object?)machineId ?? DBNull.Value);
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

		internal long UpsertDpapiMasterKey(
			long machineId,
			string scope,
			string? userSid,
			string keyPath,
			string masterKeyGuid,
			bool isPreferred,
			bool? isDomain,
			int? hashContext,
			string? hash,
			string? hashLine,
			string? failureReason)
		{
			if (machineId <= 0)
				throw new ArgumentOutOfRangeException(nameof(machineId));
			if (string.IsNullOrWhiteSpace(scope))
				throw new ArgumentException("Scope must be provided.", nameof(scope));
			if (string.IsNullOrWhiteSpace(keyPath))
				throw new ArgumentException("KeyPath must be provided.", nameof(keyPath));
			if (string.IsNullOrWhiteSpace(masterKeyGuid))
				throw new ArgumentException("MasterKeyGuid must be provided.", nameof(masterKeyGuid));

			var now = UtcNowIso8601();

			using var cmd = _connection.CreateCommand();
			cmd.CommandText = @"
INSERT INTO dpapi_masterkeys(machine_id, scope, user_sid, key_path, master_key_guid, is_preferred, is_domain, hash_context, hash, hash_line, failure_reason, first_seen_utc, last_seen_utc)
VALUES ($machine_id, $scope, $user_sid, $key_path, $master_key_guid, $is_preferred, $is_domain, $hash_context, $hash, $hash_line, $failure_reason, $now, $now)
ON CONFLICT(machine_id, master_key_guid) DO UPDATE SET
  scope=excluded.scope,
  user_sid=COALESCE(excluded.user_sid, user_sid),
  key_path=COALESCE(excluded.key_path, key_path),
  is_preferred=excluded.is_preferred,
  is_domain=COALESCE(excluded.is_domain, is_domain),
  hash_context=COALESCE(excluded.hash_context, hash_context),
  hash=COALESCE(excluded.hash, hash),
  hash_line=COALESCE(excluded.hash_line, hash_line),
  failure_reason=CASE WHEN excluded.failure_reason IS NOT NULL THEN excluded.failure_reason ELSE failure_reason END,
  last_seen_utc=$now
RETURNING dpapi_masterkey_id;";

			cmd.Parameters.AddWithValue("$machine_id", machineId);
			cmd.Parameters.AddWithValue("$scope", scope.Trim());
			cmd.Parameters.AddWithValue("$user_sid", (object?)userSid ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$key_path", keyPath.Trim());
			cmd.Parameters.AddWithValue("$master_key_guid", masterKeyGuid.Trim());
			cmd.Parameters.AddWithValue("$is_preferred", isPreferred ? 1 : 0);
			cmd.Parameters.AddWithValue("$is_domain", isDomain.HasValue ? (isDomain.Value ? 1 : 0) : (object)DBNull.Value);
			cmd.Parameters.AddWithValue("$hash_context", (object?)hashContext ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$hash", (object?)hash ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$hash_line", (object?)hashLine ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$failure_reason", (object?)failureReason ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$now", now);

			return (long)cmd.ExecuteScalar()!;
		}

		internal long UpsertDpapiBlob(
			long machineId,
			string blobKey,
			string source,
			string path,
			string? valueName,
			int? valueType,
			int? dataLength,
			long? fileSize,
			int matchOffset,
			int bytesScanned,
			string? credentialGuid,
			string? masterKeyGuid,
			uint? flags,
			string? description,
			uint? cryptAlgorithmId,
			uint? hashAlgorithmId,
			string? parseFailureReason)
		{
			if (machineId <= 0)
				throw new ArgumentOutOfRangeException(nameof(machineId));
			if (string.IsNullOrWhiteSpace(blobKey))
				throw new ArgumentException("BlobKey must be provided.", nameof(blobKey));
			if (string.IsNullOrWhiteSpace(source))
				throw new ArgumentException("Source must be provided.", nameof(source));
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("Path must be provided.", nameof(path));
			if (matchOffset < 0)
				throw new ArgumentOutOfRangeException(nameof(matchOffset));
			if (bytesScanned < 0)
				throw new ArgumentOutOfRangeException(nameof(bytesScanned));

			var now = UtcNowIso8601();
			var normalizedValueName = valueName ?? string.Empty;

			using var cmd = _connection.CreateCommand();
			cmd.CommandText = @"
INSERT INTO dpapi_blobs(machine_id, blob_key, source, path, value_name, value_type, data_length, file_size, match_offset, bytes_scanned, credential_guid, master_key_guid, flags, description, crypt_algorithm_id, hash_algorithm_id, parse_failure_reason, first_seen_utc, last_seen_utc)
VALUES ($machine_id, $blob_key, $source, $path, $value_name, $value_type, $data_length, $file_size, $match_offset, $bytes_scanned, $credential_guid, $master_key_guid, $flags, $description, $crypt_algorithm_id, $hash_algorithm_id, $parse_failure_reason, $now, $now)
ON CONFLICT(machine_id, blob_key) DO UPDATE SET
  source=excluded.source,
  path=excluded.path,
  value_name=excluded.value_name,
  value_type=COALESCE(excluded.value_type, value_type),
  data_length=COALESCE(excluded.data_length, data_length),
  file_size=COALESCE(excluded.file_size, file_size),
  match_offset=excluded.match_offset,
  bytes_scanned=excluded.bytes_scanned,
  credential_guid=COALESCE(excluded.credential_guid, credential_guid),
  master_key_guid=COALESCE(excluded.master_key_guid, master_key_guid),
  flags=COALESCE(excluded.flags, flags),
  description=COALESCE(excluded.description, description),
  crypt_algorithm_id=COALESCE(excluded.crypt_algorithm_id, crypt_algorithm_id),
  hash_algorithm_id=COALESCE(excluded.hash_algorithm_id, hash_algorithm_id),
  parse_failure_reason=CASE WHEN excluded.parse_failure_reason IS NOT NULL THEN excluded.parse_failure_reason ELSE parse_failure_reason END,
  last_seen_utc=$now
RETURNING dpapi_blob_id;";

			cmd.Parameters.AddWithValue("$machine_id", machineId);
			cmd.Parameters.AddWithValue("$blob_key", blobKey.Trim());
			cmd.Parameters.AddWithValue("$source", source.Trim());
			cmd.Parameters.AddWithValue("$path", path.Trim());
			cmd.Parameters.AddWithValue("$value_name", normalizedValueName.Trim());
			cmd.Parameters.AddWithValue("$value_type", (object?)valueType ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$data_length", (object?)dataLength ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$file_size", (object?)fileSize ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$match_offset", matchOffset);
			cmd.Parameters.AddWithValue("$bytes_scanned", bytesScanned);
			cmd.Parameters.AddWithValue("$credential_guid", (object?)credentialGuid ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$master_key_guid", (object?)masterKeyGuid ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$flags", flags.HasValue ? unchecked((long)flags.Value) : (object)DBNull.Value);
			cmd.Parameters.AddWithValue("$description", (object?)description ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$crypt_algorithm_id", cryptAlgorithmId.HasValue ? unchecked((long)cryptAlgorithmId.Value) : (object)DBNull.Value);
			cmd.Parameters.AddWithValue("$hash_algorithm_id", hashAlgorithmId.HasValue ? unchecked((long)hashAlgorithmId.Value) : (object)DBNull.Value);
			cmd.Parameters.AddWithValue("$parse_failure_reason", (object?)parseFailureReason ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$now", now);

			return (long)cmd.ExecuteScalar()!;
		}

		internal long InsertWriteActivity(
			long machineId,
			string cmdlet,
			string kind,
			string action,
			string target,
			string path,
			string? valueName,
			int? valueType,
			string? beforeBlobKind,
			byte[]? beforeBlob,
			string? afterBlobKind,
			byte[]? afterBlob,
			string? contextJson,
			bool success,
			string? failureReason,
			DateTime? activityUtc = null)
		{
			if (machineId <= 0)
				throw new ArgumentOutOfRangeException(nameof(machineId));
			if (string.IsNullOrWhiteSpace(cmdlet))
				throw new ArgumentException("Cmdlet must be provided.", nameof(cmdlet));
			if (string.IsNullOrWhiteSpace(kind))
				throw new ArgumentException("Kind must be provided.", nameof(kind));
			if (string.IsNullOrWhiteSpace(action))
				throw new ArgumentException("Action must be provided.", nameof(action));
			if (string.IsNullOrWhiteSpace(target))
				throw new ArgumentException("Target must be provided.", nameof(target));
			if (string.IsNullOrWhiteSpace(path))
				throw new ArgumentException("Path must be provided.", nameof(path));

			var now = (activityUtc ?? DateTime.UtcNow).ToString("O", CultureInfo.InvariantCulture);
			var normalizedValueName = valueName ?? string.Empty;

			using var cmd = _connection.CreateCommand();
			cmd.CommandText = @"
INSERT INTO write_activities(
  machine_id,
  cmdlet,
  kind,
  action,
  target,
  path,
  value_name,
  value_type,
  before_blob_kind,
  before_blob,
  after_blob_kind,
  after_blob,
  context_json,
  success,
  failure_reason,
  activity_utc
)
VALUES (
  $machine_id,
  $cmdlet,
  $kind,
  $action,
  $target,
  $path,
  $value_name,
  $value_type,
  $before_blob_kind,
  $before_blob,
  $after_blob_kind,
  $after_blob,
  $context_json,
  $success,
  $failure_reason,
  $activity_utc
)
RETURNING write_activity_id;";

			cmd.Parameters.AddWithValue("$machine_id", machineId);
			cmd.Parameters.AddWithValue("$cmdlet", cmdlet.Trim());
			cmd.Parameters.AddWithValue("$kind", kind.Trim());
			cmd.Parameters.AddWithValue("$action", action.Trim());
			cmd.Parameters.AddWithValue("$target", target.Trim());
			cmd.Parameters.AddWithValue("$path", path.Trim());
			cmd.Parameters.AddWithValue("$value_name", normalizedValueName.Trim());
			cmd.Parameters.AddWithValue("$value_type", (object?)valueType ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$before_blob_kind", (object?)beforeBlobKind ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$before_blob", (object?)beforeBlob ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$after_blob_kind", (object?)afterBlobKind ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$after_blob", (object?)afterBlob ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$context_json", (object?)contextJson ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$success", success ? 1 : 0);
			cmd.Parameters.AddWithValue("$failure_reason", (object?)failureReason ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$activity_utc", now);

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
			internal string Scope { get; init; } = PrincipalScopeGlobal;
			internal long? ScopeMachineId { get; init; }
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

		internal sealed class DpapiMasterKeyRow
		{
			internal long DpapiMasterKeyId { get; init; }
			internal long MachineId { get; init; }
			internal string Scope { get; init; } = "";
			internal string? UserSid { get; init; }
			internal string KeyPath { get; init; } = "";
			internal string MasterKeyGuid { get; init; } = "";
			internal bool IsPreferred { get; init; }
			internal bool? IsDomain { get; init; }
			internal int? HashContext { get; init; }
			internal string? Hash { get; init; }
			internal string? HashLine { get; init; }
			internal string? FailureReason { get; init; }
			internal string FirstSeenUtc { get; init; } = "";
			internal string LastSeenUtc { get; init; } = "";
		}

		internal sealed class DpapiBlobRow
		{
			internal long DpapiBlobId { get; init; }
			internal long MachineId { get; init; }
			internal string BlobKey { get; init; } = "";
			internal string Source { get; init; } = "";
			internal string Path { get; init; } = "";
			internal string ValueName { get; init; } = "";
			internal int? ValueType { get; init; }
			internal int? DataLength { get; init; }
			internal long? FileSize { get; init; }
			internal int MatchOffset { get; init; }
			internal int BytesScanned { get; init; }
			internal string? CredentialGuid { get; init; }
			internal string? MasterKeyGuid { get; init; }
			internal uint? Flags { get; init; }
			internal string? Description { get; init; }
			internal uint? CryptAlgorithmId { get; init; }
			internal uint? HashAlgorithmId { get; init; }
			internal string? ParseFailureReason { get; init; }
			internal string FirstSeenUtc { get; init; } = "";
			internal string LastSeenUtc { get; init; } = "";
		}

		internal IReadOnlyList<DpapiMasterKeyRow> QueryDpapiMasterKeys()
		{
			using var cmd = _connection.CreateCommand();
			cmd.CommandText = @"
SELECT
  dpapi_masterkey_id,
  machine_id,
  scope,
  user_sid,
  key_path,
  master_key_guid,
  is_preferred,
  is_domain,
  hash_context,
  hash,
  hash_line,
  failure_reason,
  first_seen_utc,
  last_seen_utc
FROM dpapi_masterkeys
ORDER BY dpapi_masterkey_id;";

			using var reader = cmd.ExecuteReader();
			var results = new List<DpapiMasterKeyRow>();
			while (reader.Read())
			{
				results.Add(new DpapiMasterKeyRow
				{
					DpapiMasterKeyId = reader.GetInt64(0),
					MachineId = reader.GetInt64(1),
					Scope = reader.GetString(2),
					UserSid = reader.IsDBNull(3) ? null : reader.GetString(3),
					KeyPath = reader.GetString(4),
					MasterKeyGuid = reader.GetString(5),
					IsPreferred = reader.GetInt64(6) != 0,
					IsDomain = reader.IsDBNull(7) ? null : reader.GetInt64(7) != 0,
					HashContext = reader.IsDBNull(8) ? null : reader.GetInt32(8),
					Hash = reader.IsDBNull(9) ? null : reader.GetString(9),
					HashLine = reader.IsDBNull(10) ? null : reader.GetString(10),
					FailureReason = reader.IsDBNull(11) ? null : reader.GetString(11),
					FirstSeenUtc = reader.GetString(12),
					LastSeenUtc = reader.GetString(13),
				});
			}

			return results;
		}

		internal IReadOnlyList<DpapiBlobRow> QueryDpapiBlobs()
		{
			using var cmd = _connection.CreateCommand();
			cmd.CommandText = @"
SELECT
  dpapi_blob_id,
  machine_id,
  blob_key,
  source,
  path,
  value_name,
  value_type,
  data_length,
  file_size,
  match_offset,
  bytes_scanned,
  credential_guid,
  master_key_guid,
  flags,
  description,
  crypt_algorithm_id,
  hash_algorithm_id,
  parse_failure_reason,
  first_seen_utc,
  last_seen_utc
FROM dpapi_blobs
ORDER BY dpapi_blob_id;";

			using var reader = cmd.ExecuteReader();
			var results = new List<DpapiBlobRow>();
			while (reader.Read())
			{
				results.Add(new DpapiBlobRow
				{
					DpapiBlobId = reader.GetInt64(0),
					MachineId = reader.GetInt64(1),
					BlobKey = reader.GetString(2),
					Source = reader.GetString(3),
					Path = reader.GetString(4),
					ValueName = reader.GetString(5),
					ValueType = reader.IsDBNull(6) ? null : reader.GetInt32(6),
					DataLength = reader.IsDBNull(7) ? null : reader.GetInt32(7),
					FileSize = reader.IsDBNull(8) ? null : reader.GetInt64(8),
					MatchOffset = reader.GetInt32(9),
					BytesScanned = reader.GetInt32(10),
					CredentialGuid = reader.IsDBNull(11) ? null : reader.GetString(11),
					MasterKeyGuid = reader.IsDBNull(12) ? null : reader.GetString(12),
					Flags = reader.IsDBNull(13) ? null : unchecked((uint)reader.GetInt64(13)),
					Description = reader.IsDBNull(14) ? null : reader.GetString(14),
					CryptAlgorithmId = reader.IsDBNull(15) ? null : unchecked((uint)reader.GetInt64(15)),
					HashAlgorithmId = reader.IsDBNull(16) ? null : unchecked((uint)reader.GetInt64(16)),
					ParseFailureReason = reader.IsDBNull(17) ? null : reader.GetString(17),
					FirstSeenUtc = reader.GetString(18),
					LastSeenUtc = reader.GetString(19),
				});
			}

			return results;
		}

		internal sealed class WriteActivityRow
		{
			internal long WriteActivityId { get; init; }
			internal long MachineId { get; init; }
			internal string Cmdlet { get; init; } = "";
			internal string Kind { get; init; } = "";
			internal string Action { get; init; } = "";
			internal string Target { get; init; } = "";
			internal string Path { get; init; } = "";
			internal string ValueName { get; init; } = "";
			internal int? ValueType { get; init; }
			internal string? BeforeBlobKind { get; init; }
			internal byte[]? BeforeBlob { get; init; }
			internal string? AfterBlobKind { get; init; }
			internal byte[]? AfterBlob { get; init; }
			internal string? ContextJson { get; init; }
			internal bool Success { get; init; }
			internal string? FailureReason { get; init; }
			internal string ActivityUtc { get; init; } = "";
		}

		internal IReadOnlyList<WriteActivityRow> QueryWriteActivities()
		{
			using var cmd = _connection.CreateCommand();
			cmd.CommandText = @"
SELECT
  write_activity_id,
  machine_id,
  cmdlet,
  kind,
  action,
  target,
  path,
  value_name,
  value_type,
  before_blob_kind,
  before_blob,
  after_blob_kind,
  after_blob,
  context_json,
  success,
  failure_reason,
  activity_utc
FROM write_activities
ORDER BY write_activity_id;";

			using var reader = cmd.ExecuteReader();
			var results = new List<WriteActivityRow>();
			while (reader.Read())
			{
				results.Add(new WriteActivityRow
				{
					WriteActivityId = reader.GetInt64(0),
					MachineId = reader.GetInt64(1),
					Cmdlet = reader.GetString(2),
					Kind = reader.GetString(3),
					Action = reader.GetString(4),
					Target = reader.GetString(5),
					Path = reader.GetString(6),
					ValueName = reader.GetString(7),
					ValueType = reader.IsDBNull(8) ? null : reader.GetInt32(8),
					BeforeBlobKind = reader.IsDBNull(9) ? null : reader.GetString(9),
					BeforeBlob = reader.IsDBNull(10) ? null : reader.GetFieldValue<byte[]>(10),
					AfterBlobKind = reader.IsDBNull(11) ? null : reader.GetString(11),
					AfterBlob = reader.IsDBNull(12) ? null : reader.GetFieldValue<byte[]>(12),
					ContextJson = reader.IsDBNull(13) ? null : reader.GetString(13),
					Success = reader.GetInt64(14) != 0,
					FailureReason = reader.IsDBNull(15) ? null : reader.GetString(15),
					ActivityUtc = reader.GetString(16),
				});
			}

			return results;
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
SELECT principal_id, scope, scope_machine_id, sid, domain, name, type, first_seen_utc, last_seen_utc
FROM principals
ORDER BY principal_id;";

			using var reader = cmd.ExecuteReader();
			var results = new List<GraphPrincipalRow>();
			while (reader.Read())
			{
				results.Add(new GraphPrincipalRow
				{
					PrincipalId = reader.GetInt64(0),
					Scope = reader.GetString(1),
					ScopeMachineId = reader.IsDBNull(2) ? null : reader.GetInt64(2),
					Sid = reader.IsDBNull(3) ? null : reader.GetString(3),
					Domain = reader.IsDBNull(4) ? null : reader.GetString(4),
					Name = reader.IsDBNull(5) ? null : reader.GetString(5),
					Type = reader.IsDBNull(6) ? null : reader.GetString(6),
					FirstSeenUtc = reader.GetString(7),
					LastSeenUtc = reader.GetString(8),
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
				"observations",
				"dpapi_masterkeys",
				"dpapi_blobs",
				"write_activities"
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
				"DELETE FROM write_activities;" +
				"DELETE FROM dpapi_blobs;" +
				"DELETE FROM dpapi_masterkeys;" +
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
					cmd.CommandText = $"DELETE FROM principals WHERE scope = '{PrincipalScopeMachine}' AND scope_machine_id IN ({inClause});";
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
