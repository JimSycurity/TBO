Set-StrictMode -Version Latest

$script:testHarnessPath = Join-Path $PSScriptRoot 'TboTestHarness.ps1'
if (Test-Path -LiteralPath $script:testHarnessPath) {
	. $script:testHarnessPath
}

Describe 'Export-TBOCacheJson' {
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

	It 'exports cache tables as JSON' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$cachePath = Join-Path $TestDrive 'cache_export.sqlite3'
		$env:TITANIS_TBO_CACHE = $cachePath

		Clear-TBOCache -Confirm:$false

		Add-TBOCacheObservation -ServerName host1 `
			-PrincipalSid 'S-1-5-18' `
			-PrincipalDomain 'NT AUTHORITY' `
			-PrincipalName 'SYSTEM' `
			-PrincipalType User `
			-CredentialKind NTHash `
			-CredentialIdentifier '8846f7eaee8fb117ad06bdd830b7586c' `
			-SourceKind Test | Out-Null

		$export = Export-TBOCacheJson | ConvertFrom-Json
		$export.schema | Should -Be 'tbo.cache.export.v1'
		$export.schemaVersion | Should -Be 3

		$export.machines.Count | Should -Be 1
		$export.principals.Count | Should -Be 1
		$export.credentials.Count | Should -Be 1
		$export.observations.Count | Should -Be 1
		$export.dpapiMasterKeys.Count | Should -Be 0
		$export.dpapiBlobs.Count | Should -Be 0

		$export.machines[0].serverName | Should -Be 'host1'
		$export.principals[0].sid | Should -Be 'S-1-5-18'
		$export.credentials[0].kind | Should -Be 'NTHash'
		$export.credentials[0].identifier | Should -Be '8846f7eaee8fb117ad06bdd830b7586c'
		$export.observations[0].sourceKind | Should -Be 'Test'
	}

	It 'exports DPAPI cache tables as JSON' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$cachePath = Join-Path $TestDrive 'cache_export_dpapi.sqlite3'
		$env:TITANIS_TBO_CACHE = $cachePath

		Clear-TBOCache -Confirm:$false

		Add-TBOCacheObservation -ServerName host1 `
			-CredentialKind NTHash `
			-CredentialIdentifier '8846f7eaee8fb117ad06bdd830b7586c' `
			-SourceKind Test | Out-Null

		$conn = [Microsoft.Data.Sqlite.SqliteConnection]::new("Data Source=$cachePath;Mode=ReadWrite;Pooling=False")
		$conn.Open()
		try {
			$cmd = $conn.CreateCommand()
			$cmd.CommandText = 'SELECT machine_id FROM machines WHERE server_name=$server;'
			$cmd.Parameters.Clear()
			$cmd.Parameters.AddWithValue('$server', 'host1') | Out-Null
			$machineId = [int64]$cmd.ExecuteScalar()

			$now = [DateTime]::UtcNow.ToString('O')

			$mkGuid = '11111111-1111-1111-1111-111111111111'
			$mkPath = '\\\\host1\\C$\\Users\\jsmith\\AppData\\Roaming\\Microsoft\\Protect\\S-1-5-21-1-2-3-1001\\' + $mkGuid
			$mkHash = '$DPAPImk$2*1*S-1-5-21-1-2-3-1001*aes256*sha512*1*00*0*00'

			$cmd.CommandText = @'
INSERT INTO dpapi_masterkeys(machine_id, scope, user_sid, key_path, master_key_guid, is_preferred, is_domain, hash_context, hash, hash_line, failure_reason, first_seen_utc, last_seen_utc)
VALUES ($machine_id, 'User', 'S-1-5-21-1-2-3-1001', $key_path, $master_key_guid, 1, 0, 1, $hash, $hash_line, NULL, $now, $now);
'@
			$cmd.Parameters.Clear()
			$cmd.Parameters.AddWithValue('$machine_id', $machineId) | Out-Null
			$cmd.Parameters.AddWithValue('$key_path', $mkPath) | Out-Null
			$cmd.Parameters.AddWithValue('$master_key_guid', $mkGuid) | Out-Null
			$cmd.Parameters.AddWithValue('$hash', $mkHash) | Out-Null
			$cmd.Parameters.AddWithValue('$hash_line', "{$mkGuid}:$mkHash") | Out-Null
			$cmd.Parameters.AddWithValue('$now', $now) | Out-Null
			$cmd.ExecuteNonQuery() | Out-Null

			$blobKey = "File|\\\\host1\\C$\\Users\\Public\\blob.bin|0"
			$cmd.CommandText = @'
INSERT INTO dpapi_blobs(machine_id, blob_key, source, path, value_name, value_type, data_length, file_size, match_offset, bytes_scanned, credential_guid, master_key_guid, flags, description, crypt_algorithm_id, hash_algorithm_id, parse_failure_reason, first_seen_utc, last_seen_utc)
VALUES ($machine_id, $blob_key, 'File', $path, '', NULL, NULL, 1234, 0, 1024, NULL, $master_key_guid, NULL, 'Local Credential Data', 26128, 32782, NULL, $now, $now);
'@
			$cmd.Parameters.Clear()
			$cmd.Parameters.AddWithValue('$machine_id', $machineId) | Out-Null
			$cmd.Parameters.AddWithValue('$blob_key', $blobKey) | Out-Null
			$cmd.Parameters.AddWithValue('$path', '\\\\host1\\C$\\Users\\Public\\blob.bin') | Out-Null
			$cmd.Parameters.AddWithValue('$master_key_guid', $mkGuid) | Out-Null
			$cmd.Parameters.AddWithValue('$now', $now) | Out-Null
			$cmd.ExecuteNonQuery() | Out-Null
		} finally {
			$conn.Dispose()
		}

		$export = Export-TBOCacheJson | ConvertFrom-Json
		$export.dpapiMasterKeys.Count | Should -Be 1
		$export.dpapiMasterKeys[0].masterKeyGuid | Should -Be $mkGuid
		$export.dpapiBlobs.Count | Should -Be 1
		$export.dpapiBlobs[0].blobKey | Should -Be $blobKey
		$export.dpapiBlobs[0].masterKeyGuid | Should -Be $mkGuid
		$export.dpapiBlobs[0].cryptAlgorithmId | Should -Be 26128
		$export.dpapiBlobs[0].hashAlgorithmId | Should -Be 32782
	}
}
