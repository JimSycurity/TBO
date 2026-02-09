Set-StrictMode -Version Latest

$script:testHarnessPath = Join-Path $PSScriptRoot 'TboTestHarness.ps1'
if (Test-Path -LiteralPath $script:testHarnessPath) {
	. $script:testHarnessPath
}

Describe 'TBO cache principal identity' {
	BeforeAll {
		$testHarnessPath = Join-Path $PSScriptRoot 'TboTestHarness.ps1'
		if (Test-Path -LiteralPath $testHarnessPath) {
			. $testHarnessPath
		}

		$script:repoRoot = Get-TboRepoRoot -Paths @($PSScriptRoot, (Get-Location).Path)
		$script:moduleAvailable = $false
		if ($script:repoRoot) {
			try {
				Import-TboModuleForTests -RepoRoot $script:repoRoot | Out-Null
				$script:moduleAvailable = $true
			} catch {
				$script:moduleAvailable = $false
			}
		}

		$script:originalCachePath = $env:TITANIS_TBO_CACHE
	}

	AfterAll {
		if ($null -eq $script:originalCachePath) {
			Remove-Item env:TITANIS_TBO_CACHE -ErrorAction SilentlyContinue
		} else {
			$env:TITANIS_TBO_CACHE = $script:originalCachePath
		}
	}

	It 'de-dupes SID-less principals by (domain,name,type) when domain is provided' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$cachePath = Join-Path $TestDrive 'cache.sqlite3'
		$env:TITANIS_TBO_CACHE = $cachePath

		Clear-TBOCache -Confirm:$false

		Add-TBOCacheObservation -ServerName host1 -PrincipalDomain host1 -PrincipalName Administrator -PrincipalType LocalUser -SourceKind Test | Out-Null
		Add-TBOCacheObservation -ServerName host1 -PrincipalDomain host1 -PrincipalName Administrator -PrincipalType LocalUser -SourceKind Test | Out-Null

		$info = Get-TBOCacheInfo
		$info.MachineCount | Should -Be 1
		$info.PrincipalCount | Should -Be 1
		$info.ObservationCount | Should -Be 2
	}

	It 'does not merge SID-less principals across different domains' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$cachePath = Join-Path $TestDrive 'cache2.sqlite3'
		$env:TITANIS_TBO_CACHE = $cachePath

		Clear-TBOCache -Confirm:$false

		Add-TBOCacheObservation -ServerName host1 -PrincipalDomain host1 -PrincipalName Administrator -PrincipalType LocalUser -SourceKind Test | Out-Null
		Add-TBOCacheObservation -ServerName host2 -PrincipalDomain host2 -PrincipalName Administrator -PrincipalType LocalUser -SourceKind Test | Out-Null

		$info = Get-TBOCacheInfo
		$info.MachineCount | Should -Be 2
		$info.PrincipalCount | Should -Be 2
		$info.ObservationCount | Should -Be 2
	}
}

Describe 'TBO cache schema v3' {
	It 'migrates a v1 cache DB to schema v3 on open' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$cachePath = Join-Path $TestDrive 'cache_v1.sqlite3'

		# Create a minimal schema v1 cache DB.
		$conn = [Microsoft.Data.Sqlite.SqliteConnection]::new("Data Source=$cachePath;Mode=ReadWriteCreate;Pooling=False")
		$conn.Open()
		try {
			$cmd = $conn.CreateCommand()

			$cmd.CommandText = "PRAGMA foreign_keys=ON;"
			$cmd.ExecuteNonQuery() | Out-Null

			$cmd.CommandText = "PRAGMA user_version=1;"
			$cmd.ExecuteNonQuery() | Out-Null

			$cmd.CommandText = @"
CREATE TABLE machines(
  machine_id INTEGER PRIMARY KEY,
  server_name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  first_seen_utc TEXT NOT NULL,
  last_seen_utc TEXT NOT NULL
);
"@
			$cmd.ExecuteNonQuery() | Out-Null

			$cmd.CommandText = @"
CREATE TABLE principals(
  principal_id INTEGER PRIMARY KEY,
  sid TEXT NULL UNIQUE COLLATE NOCASE,
  domain TEXT NULL,
  name TEXT NULL,
  type TEXT NULL,
  first_seen_utc TEXT NOT NULL,
  last_seen_utc TEXT NOT NULL
);
"@
			$cmd.ExecuteNonQuery() | Out-Null

			$cmd.CommandText = @"
CREATE TABLE credentials(
  credential_id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL,
  identifier TEXT NOT NULL,
  secret_blob BLOB NULL,
  first_seen_utc TEXT NOT NULL,
  last_seen_utc TEXT NOT NULL,
  UNIQUE(kind, identifier)
);
"@
			$cmd.ExecuteNonQuery() | Out-Null

			$cmd.CommandText = @"
CREATE TABLE observations(
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
"@
			$cmd.ExecuteNonQuery() | Out-Null
		} finally {
			$conn.Dispose()
		}

		$env:TITANIS_TBO_CACHE = $cachePath

		$info = Get-TBOCacheInfo
		$info.SchemaVersion | Should -Be 3

		# Ensure the principals table has the v2 scope columns after migration.
		$conn2 = [Microsoft.Data.Sqlite.SqliteConnection]::new("Data Source=$cachePath;Mode=ReadWrite;Pooling=False")
		$conn2.Open()
		try {
			$cmd2 = $conn2.CreateCommand()
			$cmd2.CommandText = "PRAGMA table_info(principals);"
			$reader = $cmd2.ExecuteReader()
			$cols = @()
			while ($reader.Read()) {
				$cols += $reader.GetString(1)
			}
			$reader.Dispose()

			$cols | Should -Contain 'scope'
			$cols | Should -Contain 'scope_machine_id'

			# Ensure new v3 DPAPI tables exist after migration.
			$cmd2.CommandText = "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='dpapi_masterkeys';"
			([int]$cmd2.ExecuteScalar()) | Should -Be 1
			$cmd2.CommandText = "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='dpapi_blobs';"
			([int]$cmd2.ExecuteScalar()) | Should -Be 1
		} finally {
			$conn2.Dispose()
		}
	}

	It 'exports machine-scoped principals with scoped node ids' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$cachePath = Join-Path $TestDrive 'cache_v2.sqlite3'
		$env:TITANIS_TBO_CACHE = $cachePath

		Clear-TBOCache -Confirm:$false

		# Seed machines + a machine-scoped principal directly, then validate export node ids.
		$conn = [Microsoft.Data.Sqlite.SqliteConnection]::new("Data Source=$cachePath;Mode=ReadWrite;Pooling=False")
		$conn.Open()
		try {
			$now = [DateTime]::UtcNow.ToString('O')

			$cmd = $conn.CreateCommand()

			$cmd.CommandText = 'INSERT INTO machines(server_name, first_seen_utc, last_seen_utc) VALUES ($server, $now, $now);'
			$cmd.Parameters.Clear()
			$cmd.Parameters.AddWithValue('$server', 'host1') | Out-Null
			$cmd.Parameters.AddWithValue('$now', $now) | Out-Null
			$cmd.ExecuteNonQuery() | Out-Null

			$cmd.CommandText = 'SELECT machine_id FROM machines WHERE server_name=$server;'
			$cmd.Parameters.Clear()
			$cmd.Parameters.AddWithValue('$server', 'host1') | Out-Null
			$machineId = [int64]$cmd.ExecuteScalar()

			$cmd.CommandText = @'
INSERT INTO principals(scope, scope_machine_id, sid, domain, name, type, first_seen_utc, last_seen_utc)
VALUES ('Machine', $scope_machine_id, $sid, $domain, $name, $type, $now, $now);
'@
			$cmd.Parameters.Clear()
			$cmd.Parameters.AddWithValue('$scope_machine_id', $machineId) | Out-Null
			$cmd.Parameters.AddWithValue('$sid', 'S-1-5-18') | Out-Null
			$cmd.Parameters.AddWithValue('$domain', 'NT AUTHORITY') | Out-Null
			$cmd.Parameters.AddWithValue('$name', 'SYSTEM') | Out-Null
			$cmd.Parameters.AddWithValue('$type', 'User') | Out-Null
			$cmd.Parameters.AddWithValue('$now', $now) | Out-Null
			$cmd.ExecuteNonQuery() | Out-Null

			$cmd.CommandText = "SELECT principal_id FROM principals WHERE scope='Machine' AND scope_machine_id=`$scope_machine_id AND sid=`$sid;"
			$cmd.Parameters.Clear()
			$cmd.Parameters.AddWithValue('$scope_machine_id', $machineId) | Out-Null
			$cmd.Parameters.AddWithValue('$sid', 'S-1-5-18') | Out-Null
			$principalId = [int64]$cmd.ExecuteScalar()
		} finally {
			$conn.Dispose()
		}

		$json = Export-TBOCacheGraph -Format Json | ConvertFrom-Json
		$node = $json.nodes | Where-Object { $_.type -eq 'principal' -and $_.principalId -eq $principalId } | Select-Object -First 1
		$node.id | Should -Be "principal:machine:${machineId}:${principalId}"

		$og = Export-TBOCacheGraph -Format OpenGraph | ConvertFrom-Json
		$ogNode = $og.graph.nodes | Where-Object { $_.properties.principalId -eq $principalId } | Select-Object -First 1
		$ogNode.id | Should -Be "principal:machine:${machineId}:${principalId}"

		$dot = Export-TBOCacheGraph -Format Dot
		$dot | Should -Match "pm${machineId}_${principalId}"
	}
}
