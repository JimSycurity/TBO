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

		private const int SchemaVersion = 6;
		private readonly SqliteConnection _connection;
		private readonly Action<string> _logDiagnostic;

		internal enum PrincipalScope
		{
			Global = 1,
			Machine = 2
		}

		private const string PrincipalScopeGlobal = "Global";
		private const string PrincipalScopeMachine = "Machine";

		private TboCacheDatabase(SqliteConnection connection, Action<string>? logDiagnostic)
		{
			_connection = connection ?? throw new ArgumentNullException(nameof(connection));
			_logDiagnostic = logDiagnostic ?? (_ => { });
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

			var db = new TboCacheDatabase(conn, logDiagnostic);
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
				ApplySchemaV6();
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
				SetUserVersion(4);
				userVersion = 4;
			}

			if (userVersion == 4)
			{
				logDiagnostic("TBO cache: migrating DB schema v4 -> v5.");
				MigrateSchemaV4ToV5(logDiagnostic);
				SetUserVersion(5);
				userVersion = 5;
			}

			if (userVersion == 5)
			{
				logDiagnostic("TBO cache: migrating DB schema v5 -> v6.");
				MigrateSchemaV5ToV6(logDiagnostic);
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

		private void ApplySchemaV6()
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
  cleartext_key BLOB NULL,
  cleartext_key_sha1 TEXT NULL COLLATE NOCASE,
  failure_reason TEXT NULL,
  first_seen_utc TEXT NOT NULL,
  last_seen_utc TEXT NOT NULL,
  UNIQUE(machine_id, master_key_guid)
);
", tx);

			Exec("CREATE INDEX IF NOT EXISTS idx_dpapi_masterkeys_machine_id ON dpapi_masterkeys(machine_id);", tx);
			Exec("CREATE INDEX IF NOT EXISTS idx_dpapi_masterkeys_master_key_guid ON dpapi_masterkeys(master_key_guid);", tx);
			Exec("CREATE INDEX IF NOT EXISTS idx_dpapi_masterkeys_cleartext_sha1 ON dpapi_masterkeys(cleartext_key_sha1) WHERE cleartext_key_sha1 IS NOT NULL;", tx);

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

			// v6: verified password hashes. Populated by cmdlets that cryptographically confirm a
			// password/NT hash (e.g. a successful DPAPI master key decrypt or CREDHIST chain decrypt).
			// Other cmdlets on subsequent runs can re-use these hashes without requiring the plaintext
			// password again. See bead TBO-7xo and the triage-cmdlet consumer TBO-txp.
			Exec(@"
CREATE TABLE IF NOT EXISTS verified_password_hashes(
  verified_password_hash_id INTEGER PRIMARY KEY,
  machine_id INTEGER NOT NULL REFERENCES machines(machine_id) ON DELETE CASCADE,
  server_name TEXT NOT NULL COLLATE NOCASE,
  user_sid TEXT NOT NULL COLLATE NOCASE,
  user_name TEXT NULL,
  hash_type TEXT NOT NULL,
  hash_value TEXT NOT NULL COLLATE NOCASE,
  verified_by_cmdlet TEXT NOT NULL,
  verified_via TEXT NOT NULL,
  first_seen_utc TEXT NOT NULL,
  last_seen_utc TEXT NOT NULL,
  UNIQUE(machine_id, user_sid, hash_type, hash_value)
);
", tx);

			Exec("CREATE INDEX IF NOT EXISTS idx_verified_password_hashes_machine_id ON verified_password_hashes(machine_id);", tx);
			Exec("CREATE INDEX IF NOT EXISTS idx_verified_password_hashes_server_sid ON verified_password_hashes(server_name, user_sid);", tx);
			Exec("CREATE INDEX IF NOT EXISTS idx_verified_password_hashes_server ON verified_password_hashes(server_name);", tx);

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

		// v5 adds two columns to dpapi_masterkeys so cmdlets that recover the actual cleartext
		// master key (e.g. Invoke-TBODpapiMasterKeyBkrp via the Bleichenbacher oracle attack) can
		// persist the recovered material — not just the hashcat-format $DPAPImk$ hash that v4 stored.
		//   - cleartext_key BLOB:        the recovered raw key bytes (typically 64 bytes for DPAPI)
		//   - cleartext_key_sha1 TEXT:   SHA-1 hash of the cleartext, used by DPAPI itself to identify
		//                                which master key decrypts a given blob (so this is the natural
		//                                index for "do I already have the key for this blob?" queries)
		private void MigrateSchemaV4ToV5(Action<string> logDiagnostic)
		{
			using var tx = _connection.BeginTransaction();

			Exec("ALTER TABLE dpapi_masterkeys ADD COLUMN cleartext_key BLOB NULL;", tx);
			Exec("ALTER TABLE dpapi_masterkeys ADD COLUMN cleartext_key_sha1 TEXT NULL COLLATE NOCASE;", tx);
			Exec("CREATE INDEX IF NOT EXISTS idx_dpapi_masterkeys_cleartext_sha1 ON dpapi_masterkeys(cleartext_key_sha1) WHERE cleartext_key_sha1 IS NOT NULL;", tx);

			tx.Commit();

			logDiagnostic("TBO cache: migration to schema v5 complete.");
		}

		// v6 adds the verified_password_hashes table: a cross-cmdlet stash of password / NT hashes
		// that have been cryptographically *verified* (not merely guessed). Downstream cmdlets can
		// load these as candidate key material without the user having to re-supply plaintext.
		//
		// Entries are *only* written after cryptographic confirmation (e.g. successful DPAPI master
		// key decrypt or CREDHIST chain decrypt). Failed/unverified attempts do NOT belong here —
		// see bead TBO-7xo.
		private void MigrateSchemaV5ToV6(Action<string> logDiagnostic)
		{
			using var tx = _connection.BeginTransaction();

			Exec(@"
CREATE TABLE IF NOT EXISTS verified_password_hashes(
  verified_password_hash_id INTEGER PRIMARY KEY,
  machine_id INTEGER NOT NULL REFERENCES machines(machine_id) ON DELETE CASCADE,
  server_name TEXT NOT NULL COLLATE NOCASE,
  user_sid TEXT NOT NULL COLLATE NOCASE,
  user_name TEXT NULL,
  hash_type TEXT NOT NULL,
  hash_value TEXT NOT NULL COLLATE NOCASE,
  verified_by_cmdlet TEXT NOT NULL,
  verified_via TEXT NOT NULL,
  first_seen_utc TEXT NOT NULL,
  last_seen_utc TEXT NOT NULL,
  UNIQUE(machine_id, user_sid, hash_type, hash_value)
);
", tx);

			Exec("CREATE INDEX IF NOT EXISTS idx_verified_password_hashes_machine_id ON verified_password_hashes(machine_id);", tx);
			Exec("CREATE INDEX IF NOT EXISTS idx_verified_password_hashes_server_sid ON verified_password_hashes(server_name, user_sid);", tx);
			Exec("CREATE INDEX IF NOT EXISTS idx_verified_password_hashes_server ON verified_password_hashes(server_name);", tx);

			tx.Commit();

			logDiagnostic("TBO cache: migration to schema v6 complete.");
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

			var normalizedKind = kind.Trim();
			var persistedSecretBlob = secretBlob;
			if (persistedSecretBlob != null
				&& persistedSecretBlob.Length > 0
				&& normalizedKind.Equals("dpapi_cleartext", StringComparison.OrdinalIgnoreCase))
			{
				persistedSecretBlob = TboCacheProtection.ProtectDpapiPayloadForStorage(
					persistedSecretBlob,
					contextLabel: $"credentials.secret_blob/{normalizedKind}");
			}

			var now = UtcNowIso8601();

			using var cmd = _connection.CreateCommand();
			cmd.CommandText = @"
INSERT INTO credentials(kind, identifier, secret_blob, first_seen_utc, last_seen_utc)
VALUES ($kind, $identifier, $secret_blob, $now, $now)
ON CONFLICT(kind, identifier) DO UPDATE SET
  last_seen_utc=$now
RETURNING credential_id;";

			cmd.Parameters.AddWithValue("$kind", normalizedKind);
			cmd.Parameters.AddWithValue("$identifier", identifier);
			cmd.Parameters.AddWithValue("$secret_blob", (object?)persistedSecretBlob ?? DBNull.Value);
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
			string? failureReason,
			byte[]? cleartextKey = null,
			string? cleartextKeySha1 = null)
		{
			if (machineId <= 0)
				throw new ArgumentOutOfRangeException(nameof(machineId));
			if (string.IsNullOrWhiteSpace(scope))
				throw new ArgumentException("Scope must be provided.", nameof(scope));
			if (string.IsNullOrWhiteSpace(keyPath))
				throw new ArgumentException("KeyPath must be provided.", nameof(keyPath));
			if (string.IsNullOrWhiteSpace(masterKeyGuid))
				throw new ArgumentException("MasterKeyGuid must be provided.", nameof(masterKeyGuid));

			var persistedCleartextKey = cleartextKey;
			if (persistedCleartextKey != null && persistedCleartextKey.Length > 0)
			{
				persistedCleartextKey = TboCacheProtection.ProtectDpapiPayloadForStorage(
					persistedCleartextKey,
					contextLabel: "dpapi_masterkeys.cleartext_key");
			}

			var now = UtcNowIso8601();

			using var cmd = _connection.CreateCommand();
			// COALESCE on the cleartext columns preserves any previously stored value when an
			// upsert is invoked without it (e.g. a later Get-TBODpapiMasterKeyHashes pass that
			// only knows the hashcat-format hash should not wipe a recovered cleartext key).
			cmd.CommandText = @"
INSERT INTO dpapi_masterkeys(machine_id, scope, user_sid, key_path, master_key_guid, is_preferred, is_domain, hash_context, hash, hash_line, cleartext_key, cleartext_key_sha1, failure_reason, first_seen_utc, last_seen_utc)
VALUES ($machine_id, $scope, $user_sid, $key_path, $master_key_guid, $is_preferred, $is_domain, $hash_context, $hash, $hash_line, $cleartext_key, $cleartext_key_sha1, $failure_reason, $now, $now)
ON CONFLICT(machine_id, master_key_guid) DO UPDATE SET
  scope=excluded.scope,
  user_sid=COALESCE(excluded.user_sid, user_sid),
  key_path=COALESCE(excluded.key_path, key_path),
  is_preferred=excluded.is_preferred,
  is_domain=COALESCE(excluded.is_domain, is_domain),
  hash_context=COALESCE(excluded.hash_context, hash_context),
  hash=COALESCE(excluded.hash, hash),
  hash_line=COALESCE(excluded.hash_line, hash_line),
  cleartext_key=COALESCE(excluded.cleartext_key, cleartext_key),
  cleartext_key_sha1=COALESCE(excluded.cleartext_key_sha1, cleartext_key_sha1),
  failure_reason=CASE
    WHEN excluded.cleartext_key IS NOT NULL THEN NULL
    WHEN excluded.failure_reason IS NOT NULL THEN excluded.failure_reason
    ELSE failure_reason
  END,
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
			cmd.Parameters.AddWithValue("$cleartext_key", (object?)persistedCleartextKey ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$cleartext_key_sha1", (object?)cleartextKeySha1 ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$failure_reason", (object?)failureReason ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$now", now);

			return (long)cmd.ExecuteScalar()!;
		}

		internal long UpsertDpapiMasterKeyTarget(
			long machineId,
			string masterKeyGuid,
			string sourcePath,
			string? failureReason)
		{
			if (string.IsNullOrWhiteSpace(sourcePath))
				sourcePath = $"target:{masterKeyGuid}";

			var reason = string.IsNullOrWhiteSpace(failureReason)
				? "Master key observed from protected data but cleartext key is not yet available."
				: failureReason;

			return UpsertDpapiMasterKey(
				machineId: machineId,
				scope: "Unknown",
				userSid: null,
				keyPath: sourcePath,
				masterKeyGuid: masterKeyGuid,
				isPreferred: false,
				isDomain: null,
				hashContext: null,
				hash: null,
				hashLine: null,
				failureReason: reason,
				cleartextKey: null,
				cleartextKeySha1: null);
		}

		internal (bool Exists, bool HasCleartext) GetDpapiMasterKeyPresence(
			long machineId,
			string masterKeyGuid)
		{
			if (machineId <= 0)
				throw new ArgumentOutOfRangeException(nameof(machineId));
			if (string.IsNullOrWhiteSpace(masterKeyGuid))
				throw new ArgumentException("MasterKeyGuid must be provided.", nameof(masterKeyGuid));

			using var cmd = _connection.CreateCommand();
			cmd.CommandText = @"
SELECT cleartext_key
FROM dpapi_masterkeys
WHERE machine_id = $machine_id
  AND master_key_guid = $master_key_guid
LIMIT 1;";
			cmd.Parameters.AddWithValue("$machine_id", machineId);
			cmd.Parameters.AddWithValue("$master_key_guid", masterKeyGuid.Trim());

			using var reader = cmd.ExecuteReader();
			if (!reader.Read())
				return (false, false);

			if (reader.IsDBNull(0))
				return (true, false);

			var persistedPayload = (byte[])reader.GetValue(0);
			if (!TboCacheProtection.TryUnprotectDpapiPayloadFromStorage(
				persistedPayload,
				contextLabel: $"dpapi_masterkeys/{masterKeyGuid}",
				logDiagnostic: _logDiagnostic,
				out var cleartextKey,
				out _))
			{
				return (true, false);
			}

			return (true, cleartextKey.Length > 0);
		}

		/// <summary>
		/// Inserts or updates a verified password/NT hash for a principal observed on <paramref name="serverName"/>.
		/// </summary>
		/// <remarks>
		/// Only call after cryptographic confirmation that <paramref name="hashValueHex"/> is correct
		/// (for example, after a successful DPAPI master key decrypt). Callers should never persist
		/// guesses or unverified candidates. The <paramref name="verifiedByCmdlet"/> / <paramref name="verifiedVia"/>
		/// fields are provenance-only; no reader should branch on them (new callers = new string value,
		/// no enum / no switch). See bead TBO-7xo and the triage consumer TBO-txp.
		/// </remarks>
		internal long UpsertVerifiedPasswordHash(
			long machineId,
			string serverName,
			string userSid,
			string? userName,
			string hashType,
			string hashValueHex,
			string verifiedByCmdlet,
			string verifiedVia)
		{
			if (machineId <= 0)
				throw new ArgumentOutOfRangeException(nameof(machineId));
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("ServerName must be provided.", nameof(serverName));
			if (string.IsNullOrWhiteSpace(userSid))
				throw new ArgumentException("UserSid must be provided.", nameof(userSid));
			if (string.IsNullOrWhiteSpace(hashType))
				throw new ArgumentException("HashType must be provided.", nameof(hashType));
			if (string.IsNullOrWhiteSpace(hashValueHex))
				throw new ArgumentException("HashValueHex must be provided.", nameof(hashValueHex));
			if (string.IsNullOrWhiteSpace(verifiedByCmdlet))
				throw new ArgumentException("VerifiedByCmdlet must be provided.", nameof(verifiedByCmdlet));
			if (string.IsNullOrWhiteSpace(verifiedVia))
				throw new ArgumentException("VerifiedVia must be provided.", nameof(verifiedVia));

			var now = UtcNowIso8601();

			using var cmd = _connection.CreateCommand();
			// COALESCE on user_name lets a caller that learned the login name later ("DOMAIN\\alice")
			// populate it without a caller that only knew the SID clobbering it back to NULL.
			// The provenance fields (verified_by_cmdlet, verified_via) are stamped on most-recent-write
			// so the "last cmdlet to see this hash" is always retrievable.
			cmd.CommandText = @"
INSERT INTO verified_password_hashes(machine_id, server_name, user_sid, user_name, hash_type, hash_value, verified_by_cmdlet, verified_via, first_seen_utc, last_seen_utc)
VALUES ($machine_id, $server_name, $user_sid, $user_name, $hash_type, $hash_value, $verified_by_cmdlet, $verified_via, $now, $now)
ON CONFLICT(machine_id, user_sid, hash_type, hash_value) DO UPDATE SET
  server_name=excluded.server_name,
  user_name=COALESCE(excluded.user_name, user_name),
  verified_by_cmdlet=excluded.verified_by_cmdlet,
  verified_via=excluded.verified_via,
  last_seen_utc=$now
RETURNING verified_password_hash_id;";

			cmd.Parameters.AddWithValue("$machine_id", machineId);
			cmd.Parameters.AddWithValue("$server_name", serverName.Trim());
			cmd.Parameters.AddWithValue("$user_sid", userSid.Trim());
			cmd.Parameters.AddWithValue("$user_name", (object?)userName ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$hash_type", hashType.Trim());
			cmd.Parameters.AddWithValue("$hash_value", hashValueHex.Trim());
			cmd.Parameters.AddWithValue("$verified_by_cmdlet", verifiedByCmdlet.Trim());
			cmd.Parameters.AddWithValue("$verified_via", verifiedVia.Trim());
			cmd.Parameters.AddWithValue("$now", now);

			return (long)cmd.ExecuteScalar()!;
		}

		/// <summary>
		/// Row from the <c>verified_password_hashes</c> table. All timestamps are ISO-8601 UTC strings.
		/// </summary>
		internal sealed class VerifiedPasswordHashRow
		{
			public long VerifiedPasswordHashId { get; init; }
			public long MachineId { get; init; }
			public string ServerName { get; init; } = string.Empty;
			public string UserSid { get; init; } = string.Empty;
			public string? UserName { get; init; }
			public string HashType { get; init; } = string.Empty;
			public string HashValueHex { get; init; } = string.Empty;
			public string VerifiedByCmdlet { get; init; } = string.Empty;
			public string VerifiedVia { get; init; } = string.Empty;
			public string FirstSeenUtc { get; init; } = string.Empty;
			public string LastSeenUtc { get; init; } = string.Empty;
		}

		/// <summary>
		/// Returns verified hashes for <paramref name="serverName"/>, optionally narrowed to
		/// <paramref name="userSid"/>. Pass <see langword="null"/> for <paramref name="userSid"/>
		/// to bulk-load every user on the host (the triage-cmdlet pattern — TBO-txp).
		/// </summary>
		internal IReadOnlyList<VerifiedPasswordHashRow> QueryVerifiedPasswordHashes(string serverName, string? userSid)
		{
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("ServerName must be provided.", nameof(serverName));

			using var cmd = _connection.CreateCommand();
			if (userSid is null)
			{
				cmd.CommandText = @"
SELECT verified_password_hash_id, machine_id, server_name, user_sid, user_name, hash_type, hash_value, verified_by_cmdlet, verified_via, first_seen_utc, last_seen_utc
FROM verified_password_hashes
WHERE server_name = $server_name
ORDER BY user_sid, hash_type, hash_value;";
				cmd.Parameters.AddWithValue("$server_name", serverName.Trim());
			}
			else
			{
				cmd.CommandText = @"
SELECT verified_password_hash_id, machine_id, server_name, user_sid, user_name, hash_type, hash_value, verified_by_cmdlet, verified_via, first_seen_utc, last_seen_utc
FROM verified_password_hashes
WHERE server_name = $server_name AND user_sid = $user_sid
ORDER BY hash_type, hash_value;";
				cmd.Parameters.AddWithValue("$server_name", serverName.Trim());
				cmd.Parameters.AddWithValue("$user_sid", userSid.Trim());
			}

			var results = new List<VerifiedPasswordHashRow>();
			using var reader = cmd.ExecuteReader();
			while (reader.Read())
			{
				results.Add(new VerifiedPasswordHashRow
				{
					VerifiedPasswordHashId = reader.GetInt64(0),
					MachineId = reader.GetInt64(1),
					ServerName = reader.GetString(2),
					UserSid = reader.GetString(3),
					UserName = reader.IsDBNull(4) ? null : reader.GetString(4),
					HashType = reader.GetString(5),
					HashValueHex = reader.GetString(6),
					VerifiedByCmdlet = reader.GetString(7),
					VerifiedVia = reader.GetString(8),
					FirstSeenUtc = reader.GetString(9),
					LastSeenUtc = reader.GetString(10),
				});
			}

			return results;
		}

		/// <summary>
		/// Returns SID-linked NT hash credentials observed on <paramref name="serverName"/> via the
		/// graph tables (<c>observations</c> + <c>principals</c> + <c>credentials</c>).
		/// This allows DPAPI cmdlets to correlate SAM-recovered NT hashes with user SIDs even when
		/// the hashes have not yet been promoted to <c>verified_password_hashes</c>.
		/// </summary>
		internal sealed class ObservedNtlmHashRow
		{
			public string UserSid { get; init; } = string.Empty;
			public string HashValue { get; init; } = string.Empty;
			public string SourceKind { get; init; } = string.Empty;
			public string ObservedUtc { get; init; } = string.Empty;
		}

		internal IReadOnlyList<ObservedNtlmHashRow> QueryObservedNtlmHashes(string serverName, string? userSid)
		{
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("ServerName must be provided.", nameof(serverName));

			using var cmd = _connection.CreateCommand();
			if (string.IsNullOrWhiteSpace(userSid))
			{
				cmd.CommandText = @"
SELECT
  p.sid,
  c.identifier,
  o.source_kind,
  o.observed_utc
FROM observations o
JOIN machines m ON m.machine_id = o.machine_id
JOIN principals p ON p.principal_id = o.principal_id
JOIN credentials c ON c.credential_id = o.credential_id
WHERE m.server_name = $server_name COLLATE NOCASE
  AND p.sid IS NOT NULL
  AND c.kind = 'NTHash'
ORDER BY p.sid, o.observed_utc DESC, c.last_seen_utc DESC;";
				cmd.Parameters.AddWithValue("$server_name", serverName.Trim());
			}
			else
			{
				cmd.CommandText = @"
SELECT
  p.sid,
  c.identifier,
  o.source_kind,
  o.observed_utc
FROM observations o
JOIN machines m ON m.machine_id = o.machine_id
JOIN principals p ON p.principal_id = o.principal_id
JOIN credentials c ON c.credential_id = o.credential_id
WHERE m.server_name = $server_name COLLATE NOCASE
  AND p.sid = $user_sid COLLATE NOCASE
  AND c.kind = 'NTHash'
ORDER BY o.observed_utc DESC, c.last_seen_utc DESC;";
				cmd.Parameters.AddWithValue("$server_name", serverName.Trim());
				cmd.Parameters.AddWithValue("$user_sid", userSid.Trim());
			}

			var results = new List<ObservedNtlmHashRow>();
			using var reader = cmd.ExecuteReader();
			while (reader.Read())
			{
				results.Add(new ObservedNtlmHashRow
				{
					UserSid = reader.GetString(0),
					HashValue = reader.GetString(1),
					SourceKind = reader.GetString(2),
					ObservedUtc = reader.GetString(3),
				});
			}

			return results;
		}

		internal IReadOnlyList<string> QueryObservedCredentialIdentifiers(string serverName, string credentialKind, int maxCount = 8)
		{
			if (string.IsNullOrWhiteSpace(serverName))
				throw new ArgumentException("ServerName must be provided.", nameof(serverName));
			if (string.IsNullOrWhiteSpace(credentialKind))
				throw new ArgumentException("Credential kind must be provided.", nameof(credentialKind));
			if (maxCount <= 0)
				throw new ArgumentOutOfRangeException(nameof(maxCount), "Max count must be greater than zero.");

			using var cmd = _connection.CreateCommand();
			cmd.CommandText = @"
SELECT
  c.identifier,
  MAX(o.observed_utc) AS last_observed_utc
FROM observations o
JOIN machines m ON m.machine_id = o.machine_id
JOIN credentials c ON c.credential_id = o.credential_id
WHERE m.server_name = $server_name COLLATE NOCASE
  AND c.kind = $credential_kind COLLATE NOCASE
GROUP BY c.identifier
ORDER BY last_observed_utc DESC, c.identifier ASC
LIMIT $max_count;";
			cmd.Parameters.AddWithValue("$server_name", serverName.Trim());
			cmd.Parameters.AddWithValue("$credential_kind", credentialKind.Trim());
			cmd.Parameters.AddWithValue("$max_count", maxCount);

			var results = new List<string>();
			using var reader = cmd.ExecuteReader();
			while (reader.Read())
			{
				if (reader.IsDBNull(0))
					continue;

				var identifier = reader.GetString(0);
				if (string.IsNullOrWhiteSpace(identifier))
					continue;

				results.Add(identifier);
			}

			return results;
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
			long matchOffset,
			long bytesScanned,
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

		internal sealed class ObservationFindingRow
		{
			internal long ObservationId { get; init; }
			internal long MachineId { get; init; }
			internal string ServerName { get; init; } = "";

			internal long? PrincipalId { get; init; }
			internal string? PrincipalScope { get; init; }
			internal long? PrincipalScopeMachineId { get; init; }
			internal string? PrincipalSid { get; init; }
			internal string? PrincipalDomain { get; init; }
			internal string? PrincipalName { get; init; }
			internal string? PrincipalType { get; init; }

			internal long? CredentialId { get; init; }
			internal string? CredentialKind { get; init; }
			internal string? CredentialIdentifier { get; init; }

			internal string SourceKind { get; init; } = "";
			internal string? SourcePath { get; init; }
			internal string ObservedUtc { get; init; } = "";
			internal string? ContextJson { get; init; }
			internal int? Confidence { get; init; }
		}

		internal IReadOnlyList<ObservationFindingRow> QueryObservationFindings(
			string? serverName = null,
			string? principalSid = null,
			string? principalDomain = null,
			string? principalName = null,
			string? principalType = null,
			string? credentialKind = null,
			string? credentialIdentifier = null,
			string? sourceKind = null,
			string? sourcePath = null)
		{
			serverName = string.IsNullOrWhiteSpace(serverName) ? null : serverName.Trim();
			principalSid = string.IsNullOrWhiteSpace(principalSid) ? null : principalSid.Trim();
			principalDomain = string.IsNullOrWhiteSpace(principalDomain) ? null : principalDomain.Trim();
			principalName = string.IsNullOrWhiteSpace(principalName) ? null : principalName.Trim();
			principalType = string.IsNullOrWhiteSpace(principalType) ? null : principalType.Trim();
			credentialKind = string.IsNullOrWhiteSpace(credentialKind) ? null : credentialKind.Trim();
			credentialIdentifier = string.IsNullOrWhiteSpace(credentialIdentifier) ? null : credentialIdentifier.Trim();
			sourceKind = string.IsNullOrWhiteSpace(sourceKind) ? null : sourceKind.Trim();
			sourcePath = string.IsNullOrWhiteSpace(sourcePath) ? null : sourcePath.Trim();

			using var cmd = _connection.CreateCommand();
			cmd.CommandText = @"
SELECT
  o.observation_id,
  o.machine_id,
  m.server_name,
  o.principal_id,
  p.scope,
  p.scope_machine_id,
  p.sid,
  p.domain,
  p.name,
  p.type,
  o.credential_id,
  c.kind,
  c.identifier,
  o.source_kind,
  o.source_path,
  o.observed_utc,
  o.context_json,
  o.confidence
FROM observations o
JOIN machines m ON m.machine_id = o.machine_id
LEFT JOIN principals p ON p.principal_id = o.principal_id
LEFT JOIN credentials c ON c.credential_id = o.credential_id
WHERE ($server_name IS NULL OR m.server_name = $server_name COLLATE NOCASE)
  AND ($principal_sid IS NULL OR p.sid = $principal_sid COLLATE NOCASE)
  AND ($principal_domain IS NULL OR p.domain = $principal_domain COLLATE NOCASE)
  AND ($principal_name IS NULL OR p.name = $principal_name COLLATE NOCASE)
  AND ($principal_type IS NULL OR p.type = $principal_type COLLATE NOCASE)
  AND ($credential_kind IS NULL OR c.kind = $credential_kind COLLATE NOCASE)
  AND ($credential_identifier IS NULL OR c.identifier = $credential_identifier COLLATE NOCASE)
  AND ($source_kind IS NULL OR o.source_kind = $source_kind COLLATE NOCASE)
  AND ($source_path IS NULL OR o.source_path = $source_path COLLATE NOCASE)
ORDER BY o.observed_utc DESC, o.observation_id DESC;";

			cmd.Parameters.AddWithValue("$server_name", (object?)serverName ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$principal_sid", (object?)principalSid ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$principal_domain", (object?)principalDomain ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$principal_name", (object?)principalName ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$principal_type", (object?)principalType ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$credential_kind", (object?)credentialKind ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$credential_identifier", (object?)credentialIdentifier ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$source_kind", (object?)sourceKind ?? DBNull.Value);
			cmd.Parameters.AddWithValue("$source_path", (object?)sourcePath ?? DBNull.Value);

			using var reader = cmd.ExecuteReader();
			var results = new List<ObservationFindingRow>();
			while (reader.Read())
			{
				results.Add(new ObservationFindingRow
				{
					ObservationId = reader.GetInt64(0),
					MachineId = reader.GetInt64(1),
					ServerName = reader.GetString(2),
					PrincipalId = reader.IsDBNull(3) ? null : reader.GetInt64(3),
					PrincipalScope = reader.IsDBNull(4) ? null : reader.GetString(4),
					PrincipalScopeMachineId = reader.IsDBNull(5) ? null : reader.GetInt64(5),
					PrincipalSid = reader.IsDBNull(6) ? null : reader.GetString(6),
					PrincipalDomain = reader.IsDBNull(7) ? null : reader.GetString(7),
					PrincipalName = reader.IsDBNull(8) ? null : reader.GetString(8),
					PrincipalType = reader.IsDBNull(9) ? null : reader.GetString(9),
					CredentialId = reader.IsDBNull(10) ? null : reader.GetInt64(10),
					CredentialKind = reader.IsDBNull(11) ? null : reader.GetString(11),
					CredentialIdentifier = reader.IsDBNull(12) ? null : reader.GetString(12),
					SourceKind = reader.GetString(13),
					SourcePath = reader.IsDBNull(14) ? null : reader.GetString(14),
					ObservedUtc = reader.GetString(15),
					ContextJson = reader.IsDBNull(16) ? null : reader.GetString(16),
					Confidence = reader.IsDBNull(17) ? null : reader.GetInt32(17),
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
			internal byte[]? CleartextKey { get; init; }
			internal string? CleartextKeySha1 { get; init; }
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
			internal long MatchOffset { get; init; }
			internal long BytesScanned { get; init; }
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
  cleartext_key,
  cleartext_key_sha1,
  failure_reason,
  first_seen_utc,
  last_seen_utc
FROM dpapi_masterkeys
ORDER BY dpapi_masterkey_id;";

			using var reader = cmd.ExecuteReader();
			var results = new List<DpapiMasterKeyRow>();
			while (reader.Read())
			{
				var rowId = reader.GetInt64(0);
				byte[]? cleartextKey = null;
				string? cleartextUnprotectFailure = null;
				if (!reader.IsDBNull(11))
				{
					var persistedPayload = (byte[])reader.GetValue(11);
					if (persistedPayload.Length > 0)
					{
						if (TboCacheProtection.TryUnprotectDpapiPayloadFromStorage(
							persistedPayload,
							contextLabel: $"dpapi_masterkeys/{rowId}",
							logDiagnostic: _logDiagnostic,
							out var unprotectedPayload,
							out var unprotectFailure))
						{
							cleartextKey = unprotectedPayload;
						}
						else
						{
							cleartextUnprotectFailure = unprotectFailure;
						}
					}
				}

				var failureReason = reader.IsDBNull(13) ? null : reader.GetString(13);
				if (!string.IsNullOrWhiteSpace(cleartextUnprotectFailure))
					failureReason = AppendFailureReason(failureReason, cleartextUnprotectFailure!);

				results.Add(new DpapiMasterKeyRow
				{
					DpapiMasterKeyId = rowId,
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
					CleartextKey = cleartextKey,
					CleartextKeySha1 = reader.IsDBNull(12) ? null : reader.GetString(12),
					FailureReason = failureReason,
					FirstSeenUtc = reader.GetString(14),
					LastSeenUtc = reader.GetString(15),
				});
			}

			return results;
		}

		/// <summary>
		/// Returns all decrypted master keys for a given server as a GUID→cleartext dictionary.
		/// Only rows where <c>cleartext_key IS NOT NULL</c> are included. Consumer cmdlets
		/// (Get-TBOMachineCertificates, Get-TBOChromeLogins, etc.) use this to auto-load
		/// previously-recovered keys from the cache without requiring explicit pipeline input.
		/// </summary>
		internal IReadOnlyDictionary<Guid, byte[]> QueryDecryptedMasterKeysByServer(string serverName)
		{
			if (string.IsNullOrWhiteSpace(serverName))
				return new Dictionary<Guid, byte[]>();

			using var cmd = _connection.CreateCommand();
			cmd.CommandText = @"
SELECT mk.master_key_guid, mk.cleartext_key
FROM dpapi_masterkeys mk
JOIN machines m ON m.machine_id = mk.machine_id
WHERE m.server_name = $server_name COLLATE NOCASE
  AND mk.cleartext_key IS NOT NULL;";
			cmd.Parameters.AddWithValue("$server_name", serverName);

			using var reader = cmd.ExecuteReader();
			var results = new Dictionary<Guid, byte[]>();
			while (reader.Read())
			{
				var guidStr = reader.GetString(0);
				if (!Guid.TryParse(guidStr, out var guid))
					continue;
				if (reader.IsDBNull(1))
					continue;
				var persistedPayload = (byte[])reader.GetValue(1);
				if (!TboCacheProtection.TryUnprotectDpapiPayloadFromStorage(
					persistedPayload,
					contextLabel: $"dpapi_masterkeys/{guid}",
					logDiagnostic: _logDiagnostic,
					out var keyBytes,
					out var unprotectFailure))
				{
					if (!string.IsNullOrWhiteSpace(unprotectFailure))
						_logDiagnostic($"TBO cache: unable to use cached DPAPI master key {guid} for {serverName}: {unprotectFailure}");
					continue;
				}
				if (keyBytes.Length == 0)
					continue;
				results[guid] = keyBytes;
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
					MatchOffset = reader.GetInt64(9),
					BytesScanned = reader.GetInt64(10),
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
				"verified_password_hashes",
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
				"DELETE FROM verified_password_hashes;" +
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

		private static string AppendFailureReason(string? existing, string addition)
		{
			if (string.IsNullOrWhiteSpace(existing))
				return addition;
			if (string.IsNullOrWhiteSpace(addition))
				return existing;

			return existing.TrimEnd().EndsWith(".", StringComparison.Ordinal)
				? $"{existing} {addition}"
				: $"{existing}; {addition}";
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
