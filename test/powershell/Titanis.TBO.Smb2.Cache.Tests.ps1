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

Describe 'TBO cache pivot query cmdlets (TBO-hvr.1)' {
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

	It 'supports machine, principal, credential, and source-path pivots offline' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$cachePath = Join-Path $TestDrive 'cache_pivots.sqlite3'
		$env:TITANIS_TBO_CACHE = $cachePath
		$nthash = '8846f7eaee8fb117ad06bdd830b7586c'

		Clear-TBOCache -Confirm:$false

		Add-TBOCacheObservation -ServerName host1 `
			-PrincipalDomain host1 `
			-PrincipalName Administrator `
			-PrincipalType LocalUser `
			-CredentialKind NTHash `
			-CredentialIdentifier $nthash `
			-SourceKind Get-TBORegSamHashes `
			-SourcePath '\\host1\C$\Windows\System32\config\SAM' | Out-Null

		Add-TBOCacheObservation -ServerName host2 `
			-PrincipalDomain host2 `
			-PrincipalName Administrator `
			-PrincipalType LocalUser `
			-CredentialKind NTHash `
			-CredentialIdentifier $nthash `
			-SourceKind Get-TBORegSamHashes `
			-SourcePath '\\host2\C$\Windows\System32\config\SAM' | Out-Null

		Add-TBOCacheObservation -ServerName host2 `
			-PrincipalDomain host2 `
			-PrincipalName svc_sql `
			-PrincipalType User `
			-CredentialKind Password `
			-CredentialIdentifier 'Plaintext:svc_sql' `
			-SourceKind Manual `
			-SourcePath '\\host2\C$\Users\svc_sql\secret.txt' | Out-Null

		$machineRows = @(Get-TBOCacheMachineFindings -ServerName host1)
		$machineRows.Count | Should -Be 1
		$machineRows[0].ServerName | Should -Be 'host1'
		$machineRows[0].SourcePath | Should -Be '\\host1\C$\Windows\System32\config\SAM'
		$machineRows[0].CachePath | Should -Be $cachePath

		$machineWildcardRows = @(Get-TBOCacheMachineFindings -ServerName 'host*' -SourcePath '*\Windows\System32\config\*')
		$machineWildcardRows.Count | Should -Be 2

		$principalRows = @(Get-TBOCachePrincipalFindings -Name Administrator)
		$principalRows.Count | Should -Be 2
		$principalRows | ForEach-Object { $_.PrincipalName | Should -Be 'Administrator' }

		$credentialRows = @(Get-TBOCacheCredentialFindings -Kind NTHash -Identifier $nthash.ToUpperInvariant())
		$credentialRows.Count | Should -Be 2
		$credentialRows | ForEach-Object { $_.CredentialKind | Should -Be 'NTHash' }

		$pathRows = @(Get-TBOCachePathFindings -SourcePath '*secret.txt')
		$pathRows.Count | Should -BeGreaterOrEqual 1
		$passwordPathRows = @($pathRows | Where-Object { $_.CredentialKind -eq 'Password' })
		$passwordPathRows.Count | Should -Be 1
		$passwordPathRows[0].PrincipalName | Should -Be 'svc_sql'
		$passwordPathRows[0].CredentialIdentifier | Should -Be 'Plaintext:svc_sql'
	}
}

Describe 'TBO cache credential reuse heatmap and blast radius (TBO-hvr.2)' {
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

	It 'supports offline heatmap and blast-radius ranking views' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$cachePath = Join-Path $TestDrive 'cache_reuse_scoring.sqlite3'
		$env:TITANIS_TBO_CACHE = $cachePath

		$highRiskHash = '8846f7eaee8fb117ad06bdd830b7586c'
		$lowRiskHash = 'aad3b435b51404eeaad3b435b51404ee'

		Clear-TBOCache -Confirm:$false

		Add-TBOCacheObservation -ServerName host1 `
			-PrincipalDomain host1 `
			-PrincipalName Administrator `
			-PrincipalType LocalUser `
			-CredentialKind NTHash `
			-CredentialIdentifier $highRiskHash `
			-SourceKind Get-TBORegSamHashes `
			-SourcePath '\\host1\C$\Windows\System32\config\SAM' | Out-Null

		Add-TBOCacheObservation -ServerName host2 `
			-PrincipalDomain host2 `
			-PrincipalName Administrator `
			-PrincipalType LocalUser `
			-CredentialKind NTHash `
			-CredentialIdentifier $highRiskHash `
			-SourceKind Get-TBORegSamHashes `
			-SourcePath '\\host2\C$\Windows\System32\config\SAM' | Out-Null

		Add-TBOCacheObservation -ServerName host1 `
			-PrincipalDomain host1 `
			-PrincipalName helpdesk `
			-PrincipalType User `
			-CredentialKind NTHash `
			-CredentialIdentifier $lowRiskHash `
			-SourceKind Get-TBORegSamHashes `
			-SourcePath '\\host1\C$\Windows\System32\config\SAM' | Out-Null

		Add-TBOCacheObservation -ServerName host2 `
			-PrincipalDomain host2 `
			-PrincipalName helpdesk `
			-PrincipalType User `
			-CredentialKind NTHash `
			-CredentialIdentifier $lowRiskHash `
			-SourceKind Get-TBORegSamHashes `
			-SourcePath '\\host2\C$\Windows\System32\config\SAM' | Out-Null

		$heatmap = @(Get-TBOCacheCredentialReuse -Kind NTHash -MinimumMachineCount 2 -View Heatmap)
		$heatmap.Count | Should -Be 4

		$highRiskHeatmap = @($heatmap | Where-Object { $_.CredentialIdentifier -eq $highRiskHash })
		$highRiskHeatmap.Count | Should -Be 2
		$highRiskHeatmap | ForEach-Object { $_.PrivilegeHints | Should -Contain 'Administrator' }

		$blast = @(Get-TBOCacheCredentialReuse -Kind NTHash -MinimumMachineCount 2 -View BlastRadius)
		$blast.Count | Should -Be 2
		$blast[0].CredentialIdentifier | Should -Be $highRiskHash
		$blast[0].BlastRadiusScore | Should -BeGreaterOrEqual $blast[1].BlastRadiusScore
		$blast[0].MachineCount | Should -Be 2
		$blast[0].Priority | Should -Not -BeNullOrEmpty

		$top = @(Get-TBOCacheCredentialReuse -Kind NTHash -MinimumMachineCount 2 -View BlastRadius -Top 1)
		$top.Count | Should -Be 1
		$top[0].CredentialIdentifier | Should -Be $highRiskHash
	}
}

Describe 'TBO cache derived NTHash enrichment (TBO-hvr.3)' {
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

	It 'derives and reuses NTHash observations from cached Password observations fully offline' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$cachePath = Join-Path $TestDrive 'cache_derived_nthash.sqlite3'
		$env:TITANIS_TBO_CACHE = $cachePath

		$password = 'password'
		$derivedNtHash = '8846f7eaee8fb117ad06bdd830b7586c'

		Clear-TBOCache -Confirm:$false

		Add-TBOCacheObservation -ServerName host1 `
			-PrincipalSid 'S-1-5-21-1-2-3-500' `
			-PrincipalDomain host1 `
			-PrincipalName Administrator `
			-PrincipalType LocalUser `
			-CredentialKind Password `
			-CredentialIdentifier $password `
			-SourceKind Get-TBORegLsaSecrets `
			-SourcePath '\\host1\C$\Windows\System32\config\SECURITY' | Out-Null

		Add-TBOCacheObservation -ServerName host2 `
			-PrincipalSid 'S-1-5-21-4-5-6-500' `
			-PrincipalDomain host2 `
			-PrincipalName Administrator `
			-PrincipalType LocalUser `
			-CredentialKind Password `
			-CredentialIdentifier $password `
			-SourceKind Get-TBORegLsaSecrets `
			-SourcePath '\\host2\C$\Windows\System32\config\SECURITY' | Out-Null

		$info = Get-TBOCacheInfo
		$info.MachineCount | Should -Be 2
		$info.PrincipalCount | Should -Be 2
		$info.CredentialCount | Should -Be 2
		$info.ObservationCount | Should -Be 4

		$derivedRows = @(Get-TBOCacheCredentialFindings -Kind NTHash -Identifier $derivedNtHash)
		$derivedRows.Count | Should -Be 2
		$derivedRows | ForEach-Object { $_.CredentialKind | Should -Be 'NTHash' }
		$derivedRows | ForEach-Object { $_.CredentialIdentifier | Should -Be $derivedNtHash }

		$blast = @(Get-TBOCacheCredentialReuse -Kind NTHash -Identifier $derivedNtHash -MinimumMachineCount 2 -View BlastRadius)
		$blast.Count | Should -Be 1
		$blast[0].CredentialIdentifier | Should -Be $derivedNtHash
		$blast[0].MachineCount | Should -Be 2

		$conn = [Microsoft.Data.Sqlite.SqliteConnection]::new("Data Source=$cachePath;Mode=ReadWrite;Pooling=False")
		$conn.Open()
		try {
			$cmd = $conn.CreateCommand()
			$cmd.CommandText = @'
SELECT COUNT(1)
FROM verified_password_hashes
WHERE hash_type='nt_pwd'
  AND hash_value=$hash;
'@
			$cmd.Parameters.Clear()
			$cmd.Parameters.AddWithValue('$hash', $derivedNtHash) | Out-Null
			([int]$cmd.ExecuteScalar()) | Should -Be 2
		} finally {
			$conn.Dispose()
		}
	}
}

Describe 'TBO cache DPAPI backlog and candidate ranking (TBO-hvr.4)' {
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

		if ($script:moduleAvailable) {
			$module = Get-Module -Name 'Titanis.TBO.Smb2.PowerShell'
			$assembly = $module.ImplementingAssembly
			$script:cacheDbType = $assembly.GetType('Titanis.Tbo.Smb2.PowerShell.TboCacheDatabase')
		}

		function Open-TboCacheDbReflected {
			param([string]$CachePath)
			$openMethod = $script:cacheDbType.GetMethod(
				'Open',
				[System.Reflection.BindingFlags]::Static -bor [System.Reflection.BindingFlags]::NonPublic)
			return $openMethod.Invoke($null, @($CachePath, $null))
		}

		function Invoke-UpsertMachine {
			param([object]$Db, [string]$ServerName)
			$method = $script:cacheDbType.GetMethod(
				'UpsertMachine',
				[System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic)
			return [int64]$method.Invoke($Db, @($ServerName))
		}

		function Invoke-UpsertVerifiedPasswordHash {
			param(
				[object]$Db,
				[int64]$MachineId,
				[string]$ServerName,
				[string]$UserSid,
				[string]$HashType,
				[string]$HashValueHex
			)
			$method = $script:cacheDbType.GetMethod(
				'UpsertVerifiedPasswordHash',
				[System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic)
			return [int64]$method.Invoke($Db, @(
				$MachineId, $ServerName, $UserSid, $null, $HashType, $HashValueHex, 'Get-TBODpapiMasterKeys', 'unit_test'))
		}

		function Invoke-UpsertDpapiMasterKey {
			param(
				[object]$Db,
				[int64]$MachineId,
				[string]$Scope,
				[string]$UserSid,
				[string]$KeyPath,
				[string]$MasterKeyGuid,
				[bool]$IsPreferred,
				[string]$FailureReason,
				[AllowNull()][byte[]]$CleartextKey
			)
			$method = $script:cacheDbType.GetMethod(
				'UpsertDpapiMasterKey',
				[System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic)
			$cleartextSha1 = if ($CleartextKey -and $CleartextKey.Length -gt 0) { '0123456789abcdef0123456789abcdef01234567' } else { $null }
			return [int64]$method.Invoke($Db, @(
				$MachineId, $Scope, $UserSid, $KeyPath, $MasterKeyGuid, $IsPreferred, $null, $null, $null, $null, $FailureReason, $CleartextKey, $cleartextSha1))
		}

		function Invoke-UpsertDpapiBlob {
			param(
				[object]$Db,
				[int64]$MachineId,
				[string]$BlobKey,
				[string]$Path,
				[string]$MasterKeyGuid,
				[string]$ParseFailureReason
			)
			$method = $script:cacheDbType.GetMethod(
				'UpsertDpapiBlob',
				[System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic)
			return [int64]$method.Invoke($Db, @(
				$MachineId, $BlobKey, 'File', $Path, $null, $null, 512, 1024L, 128L, 512L, $null, $MasterKeyGuid, $null, $null, $null, $null, $ParseFailureReason))
		}
	}

	AfterAll {
		if ($null -eq $script:originalCachePath) {
			Remove-Item env:TITANIS_TBO_CACHE -ErrorAction SilentlyContinue
		} else {
			$env:TITANIS_TBO_CACHE = $script:originalCachePath
		}
	}

	It 'builds unresolved DPAPI backlog and ranks candidate material offline' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$cachePath = Join-Path $TestDrive 'cache_dpapi_backlog.sqlite3'
		$env:TITANIS_TBO_CACHE = $cachePath

		$sid = 'S-1-5-21-1-2-3-500'
		$hash = '8846f7eaee8fb117ad06bdd830b7586c'
		$unresolvedGuid = '11111111-1111-1111-1111-111111111111'
		$resolvedGuid = '22222222-2222-2222-2222-222222222222'

		Clear-TBOCache -Confirm:$false

		Add-TBOCacheObservation -ServerName host1 `
			-PrincipalSid $sid `
			-PrincipalDomain host1 `
			-PrincipalName Administrator `
			-PrincipalType LocalUser `
			-CredentialKind NTHash `
			-CredentialIdentifier $hash `
			-SourceKind Get-TBORegSamHashes `
			-SourcePath '\\host1\C$\Windows\System32\config\SAM' | Out-Null

		Add-TBOCacheObservation -ServerName host1 `
			-PrincipalSid $sid `
			-PrincipalDomain host1 `
			-PrincipalName Administrator `
			-PrincipalType LocalUser `
			-CredentialKind Password `
			-CredentialIdentifier 'Password123!' `
			-SourceKind Get-TBORegLsaSecrets `
			-SourcePath '\\host1\C$\Windows\System32\config\SECURITY' | Out-Null

		$db = Open-TboCacheDbReflected -CachePath $cachePath
		try {
			$machineId = Invoke-UpsertMachine -Db $db -ServerName 'host1'
			Invoke-UpsertVerifiedPasswordHash -Db $db -MachineId $machineId -ServerName 'host1' -UserSid $sid -HashType 'nt_pwd' -HashValueHex $hash | Out-Null

			Invoke-UpsertDpapiMasterKey -Db $db -MachineId $machineId -Scope 'User' -UserSid $sid `
				-KeyPath "\\host1\C$\Users\Administrator\AppData\Roaming\Microsoft\Protect\$sid\$unresolvedGuid" `
				-MasterKeyGuid $unresolvedGuid -IsPreferred $true -FailureReason 'HMAC validation failed' -CleartextKey $null | Out-Null

			Invoke-UpsertDpapiBlob -Db $db -MachineId $machineId -BlobKey 'blob-unresolved' `
				-Path '\\host1\C$\Users\Administrator\AppData\Local\Microsoft\Credentials\A1B2C3' `
				-MasterKeyGuid $unresolvedGuid -ParseFailureReason $null | Out-Null

			[byte[]]$cleartext = 1..16
			Invoke-UpsertDpapiMasterKey -Db $db -MachineId $machineId -Scope 'User' -UserSid $sid `
				-KeyPath "\\host1\C$\Users\Administrator\AppData\Roaming\Microsoft\Protect\$sid\$resolvedGuid" `
				-MasterKeyGuid $resolvedGuid -IsPreferred $false -FailureReason $null -CleartextKey $cleartext | Out-Null

			Invoke-UpsertDpapiBlob -Db $db -MachineId $machineId -BlobKey 'blob-resolved' `
				-Path '\\host1\C$\Users\Administrator\AppData\Local\Microsoft\Credentials\D4E5F6' `
				-MasterKeyGuid $resolvedGuid -ParseFailureReason $null | Out-Null
		} finally {
			$db.Dispose()
		}

		$backlog = @(Get-TBOCacheDpapiBacklog -ServerName host1)
		$backlog.Count | Should -Be 2
		($backlog | Where-Object { $_.MasterKeyGuid -eq $resolvedGuid }).Count | Should -Be 0

		$mk = @($backlog | Where-Object { $_.ArtifactType -eq 'MasterKey' -and $_.MasterKeyGuid -eq $unresolvedGuid })[0]
		$mk.UserSid | Should -Be $sid
		$mk.HasCleartextMasterKey | Should -BeFalse
		$mk.DependentBlobCount | Should -Be 1
		$mk.CandidateCount | Should -BeGreaterThan 0

		$blob = @($backlog | Where-Object { $_.ArtifactType -eq 'Blob' -and $_.MasterKeyGuid -eq $unresolvedGuid })[0]
		$blob.HasMasterKeyRecord | Should -BeTrue
		$blob.HasCleartextMasterKey | Should -BeFalse

		$candidates = @(Get-TBOCacheDpapiBacklog -ServerName host1 -View CandidateRanking -Top 2)
		$candidates.Count | Should -BeGreaterThan 0
		$candidates[0].CandidateSourceClass | Should -Be 'VerifiedHash'
		$candidates[0].CandidateType | Should -Be 'nt_pwd'
		$candidates[0].CandidateValue | Should -Be $hash
		$candidates[0].CandidateRank | Should -Be 1

		$sidScoped = @(Get-TBOCacheDpapiBacklog -ServerName host1 -UserSid $sid)
		$sidScoped.Count | Should -Be 2
	}
}

Describe 'TBO cache schema migration' {
	It 'migrates a v1 cache DB to current schema on open' {
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
		$info.SchemaVersion | Should -Be 6

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

			# Ensure new v4 write activity table exists after migration.
			$cmd2.CommandText = "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='write_activities';"
			([int]$cmd2.ExecuteScalar()) | Should -Be 1

			# Ensure v5 added cleartext_key columns to dpapi_masterkeys.
			$cmd2.CommandText = "PRAGMA table_info(dpapi_masterkeys);"
			$reader2 = $cmd2.ExecuteReader()
			$mkCols = @()
			while ($reader2.Read()) {
				$mkCols += $reader2.GetString(1)
			}
			$reader2.Dispose()
			$mkCols | Should -Contain 'cleartext_key'
			$mkCols | Should -Contain 'cleartext_key_sha1'

			# Ensure the v6 verified_password_hashes table exists.
			$cmd2.CommandText = "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='verified_password_hashes';"
			([int]$cmd2.ExecuteScalar()) | Should -Be 1

			# And its supporting indexes.
			$cmd2.CommandText = "SELECT COUNT(1) FROM sqlite_master WHERE type='index' AND name='idx_verified_password_hashes_server_sid';"
			([int]$cmd2.ExecuteScalar()) | Should -Be 1
			$cmd2.CommandText = "SELECT COUNT(1) FROM sqlite_master WHERE type='index' AND name='idx_verified_password_hashes_server';"
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

Describe 'TBO cache verified_password_hashes (TBO-7xo)' {
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

		# Resolve the internal TboCacheDatabase type once so tests can reflect into
		# UpsertVerifiedPasswordHash / QueryVerifiedPasswordHashes directly. These are the exact
		# code paths the Get-TBODpapi* cmdlets hit, so testing them here covers writer/reader
		# semantics without standing up a mocked SMB filesystem.
		#
		# Intentionally avoid bracket type literals like [Titanis.Tbo.Smb2.PowerShell.X].Assembly —
		# under Pester v5 + StrictMode, type literals inside BeforeAll scriptblocks can fail to
		# resolve even after Import-Module, because the scriptblock was parsed before the binary
		# module was loaded. Reaching the assembly via Get-Module is fully lazy and robust.
		if ($script:moduleAvailable) {
			$module = Get-Module -Name 'Titanis.TBO.Smb2.PowerShell'
			$assembly = $module.ImplementingAssembly
			$script:cacheDbType = $assembly.GetType('Titanis.Tbo.Smb2.PowerShell.TboCacheDatabase')
		}

		# Helper functions MUST be defined inside BeforeAll so Pester v5 places them in the
		# container scope visible to It blocks. Defining them at Describe-body scope makes
		# them invisible to It blocks (Describe body runs during discovery in a throwaway scope).

		# Helper: open a TboCacheDatabase for the given cache path via reflection.
		function Open-TboCacheDbReflected {
			param([string]$CachePath)

			$openMethod = $script:cacheDbType.GetMethod(
				'Open',
				[System.Reflection.BindingFlags]::Static -bor [System.Reflection.BindingFlags]::NonPublic)
			return $openMethod.Invoke($null, @($CachePath, $null))
		}

		# Helper: invoke internal UpsertMachine and return the machine_id.
		function Invoke-UpsertMachine {
			param([object]$Db, [string]$ServerName)
			$method = $script:cacheDbType.GetMethod(
				'UpsertMachine',
				[System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic)
			return [int64]$method.Invoke($Db, @($ServerName))
		}

		# Helper: invoke internal UpsertVerifiedPasswordHash.
		# NOTE: $UserName is [AllowNull()][object] (not [string]) so the COALESCE preservation path
		# can actually be exercised — a [string] param coerces $null into "" and the C# writer
		# would then store "" in the row, defeating COALESCE(excluded.user_name, user_name).
		function Invoke-UpsertVerifiedPasswordHash {
			param(
				[object]$Db,
				[int64]$MachineId,
				[string]$ServerName,
				[string]$UserSid,
				[AllowNull()][object]$UserName,
				[string]$HashType,
				[string]$HashValueHex,
				[string]$VerifiedByCmdlet,
				[string]$VerifiedVia
			)
			$method = $script:cacheDbType.GetMethod(
				'UpsertVerifiedPasswordHash',
				[System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic)
			$userNameArg = if ($null -eq $UserName) { $null } else { [string]$UserName }
			return [int64]$method.Invoke($Db, @(
				$MachineId, $ServerName, $UserSid, $userNameArg, $HashType, $HashValueHex, $VerifiedByCmdlet, $VerifiedVia))
		}

		# Helper: invoke internal QueryVerifiedPasswordHashes and return the IReadOnlyList<VerifiedPasswordHashRow>.
		# NOTE: $UserSid is typed as [object] (not [string]) because [string] silently coerces $null
		# into an empty string via PowerShell's parameter binder — which would mask the null-SID
		# "triage bulk query" code path in QueryVerifiedPasswordHashes.
		function Invoke-QueryVerifiedPasswordHashes {
			param(
				[object]$Db,
				[string]$ServerName,
				[AllowNull()][object]$UserSid
			)
			$method = $script:cacheDbType.GetMethod(
				'QueryVerifiedPasswordHashes',
				[System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic)

			# Cast to [string] only when non-null, so $null stays $null rather than "".
			$sidArg = if ($null -eq $UserSid) { $null } else { [string]$UserSid }

			# Unary comma prevents PowerShell from enumerating the IReadOnlyList on return,
			# which would otherwise unwrap single-element results to a scalar in the caller.
			return , $method.Invoke($Db, @($ServerName, $sidArg))
		}
	}

	AfterAll {
		if ($null -eq $script:originalCachePath) {
			Remove-Item env:TITANIS_TBO_CACHE -ErrorAction SilentlyContinue
		} else {
			$env:TITANIS_TBO_CACHE = $script:originalCachePath
		}
	}

	It 'creates a fresh DB at schema v6 with the verified_password_hashes table' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$cachePath = Join-Path $TestDrive 'verified_fresh.sqlite3'
		$env:TITANIS_TBO_CACHE = $cachePath

		$info = Get-TBOCacheInfo
		$info.SchemaVersion | Should -Be 6

		$conn = [Microsoft.Data.Sqlite.SqliteConnection]::new("Data Source=$cachePath;Mode=ReadWrite;Pooling=False")
		$conn.Open()
		try {
			$cmd = $conn.CreateCommand()
			$cmd.CommandText = "SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='verified_password_hashes';"
			([int]$cmd.ExecuteScalar()) | Should -Be 1
		} finally {
			$conn.Dispose()
		}
	}

	It 'upserts a verified hash and round-trips it via QueryVerifiedPasswordHashes' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$cachePath = Join-Path $TestDrive 'verified_roundtrip.sqlite3'
		$db = Open-TboCacheDbReflected -CachePath $cachePath
		try {
			$machineId = Invoke-UpsertMachine -Db $db -ServerName 'testhost01'
			$sha1Hex = '0123456789ABCDEF0123456789ABCDEF01234567'

			Invoke-UpsertVerifiedPasswordHash -Db $db `
				-MachineId $machineId `
				-ServerName 'testhost01' `
				-UserSid 'S-1-5-21-1-2-3-1001' `
				-UserName 'alice' `
				-HashType 'sha1_pwd' `
				-HashValueHex $sha1Hex `
				-VerifiedByCmdlet 'Get-TBODpapiCredHist' `
				-VerifiedVia 'credhist_chain_decrypt' | Out-Null

			$rows = Invoke-QueryVerifiedPasswordHashes -Db $db -ServerName 'testhost01' -UserSid 'S-1-5-21-1-2-3-1001'
			$rows.Count | Should -Be 1
			$rows[0].HashType | Should -Be 'sha1_pwd'
			$rows[0].HashValueHex | Should -Be $sha1Hex
			$rows[0].UserName | Should -Be 'alice'
			$rows[0].VerifiedByCmdlet | Should -Be 'Get-TBODpapiCredHist'
			$rows[0].VerifiedVia | Should -Be 'credhist_chain_decrypt'
		} finally {
			$db.Dispose()
		}
	}

	It 'is idempotent and preserves user_name via COALESCE when a later upsert omits it' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$cachePath = Join-Path $TestDrive 'verified_coalesce.sqlite3'
		$db = Open-TboCacheDbReflected -CachePath $cachePath
		try {
			$machineId = Invoke-UpsertMachine -Db $db -ServerName 'coalesce01'
			$sha1Hex = 'AAAABBBBCCCCDDDDEEEEFFFF0000111122223333'

			# First write: SID only, no user_name.
			$id1 = Invoke-UpsertVerifiedPasswordHash -Db $db `
				-MachineId $machineId `
				-ServerName 'coalesce01' `
				-UserSid 'S-1-5-21-9-9-9-1002' `
				-UserName $null `
				-HashType 'sha1_pwd' `
				-HashValueHex $sha1Hex `
				-VerifiedByCmdlet 'Get-TBODpapiMasterKeys' `
				-VerifiedVia 'masterkey_direct_decrypt'

			# Second write: adds user_name.
			$id2 = Invoke-UpsertVerifiedPasswordHash -Db $db `
				-MachineId $machineId `
				-ServerName 'coalesce01' `
				-UserSid 'S-1-5-21-9-9-9-1002' `
				-UserName 'bob' `
				-HashType 'sha1_pwd' `
				-HashValueHex $sha1Hex `
				-VerifiedByCmdlet 'Get-TBODpapiCredHist' `
				-VerifiedVia 'credhist_chain_decrypt'

			# Third write: omits user_name again — must NOT clobber 'bob'.
			$id3 = Invoke-UpsertVerifiedPasswordHash -Db $db `
				-MachineId $machineId `
				-ServerName 'coalesce01' `
				-UserSid 'S-1-5-21-9-9-9-1002' `
				-UserName $null `
				-HashType 'sha1_pwd' `
				-HashValueHex $sha1Hex `
				-VerifiedByCmdlet 'Get-TBODpapiMasterKeys' `
				-VerifiedVia 'masterkey_direct_decrypt'

			# All three writes target the same UNIQUE key, so the row id must be identical.
			$id1 | Should -Be $id2
			$id2 | Should -Be $id3

			$rows = Invoke-QueryVerifiedPasswordHashes -Db $db -ServerName 'coalesce01' -UserSid 'S-1-5-21-9-9-9-1002'
			$rows.Count | Should -Be 1
			$rows[0].UserName | Should -Be 'bob'
			# Provenance is stamped on most-recent-write.
			$rows[0].VerifiedByCmdlet | Should -Be 'Get-TBODpapiMasterKeys'
		} finally {
			$db.Dispose()
		}
	}

	It 'stores distinct rows per (hash_type, hash_value) for the same SID' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$cachePath = Join-Path $TestDrive 'verified_distinct.sqlite3'
		$db = Open-TboCacheDbReflected -CachePath $cachePath
		try {
			$machineId = Invoke-UpsertMachine -Db $db -ServerName 'distinct01'
			$sid = 'S-1-5-21-1-1-1-1003'

			Invoke-UpsertVerifiedPasswordHash -Db $db -MachineId $machineId -ServerName 'distinct01' `
				-UserSid $sid -UserName 'carol' -HashType 'sha1_pwd' `
				-HashValueHex '1111222233334444555566667777888899990000' `
				-VerifiedByCmdlet 'Get-TBODpapiCredHist' -VerifiedVia 'credhist_chain_decrypt' | Out-Null
			Invoke-UpsertVerifiedPasswordHash -Db $db -MachineId $machineId -ServerName 'distinct01' `
				-UserSid $sid -UserName 'carol' -HashType 'nt_pwd' `
				-HashValueHex 'AABBCCDDEEFF00112233445566778899' `
				-VerifiedByCmdlet 'Get-TBODpapiCredHist' -VerifiedVia 'credhist_chain_decrypt' | Out-Null
			# A different historical sha1_pwd (from a CREDHIST entry).
			Invoke-UpsertVerifiedPasswordHash -Db $db -MachineId $machineId -ServerName 'distinct01' `
				-UserSid $sid -UserName 'carol' -HashType 'sha1_pwd' `
				-HashValueHex 'DEADBEEFCAFEBABE0123456789ABCDEFFEEDFACE' `
				-VerifiedByCmdlet 'Get-TBODpapiCredHist' -VerifiedVia 'credhist_entry' | Out-Null

			$rows = Invoke-QueryVerifiedPasswordHashes -Db $db -ServerName 'distinct01' -UserSid $sid
			$rows.Count | Should -Be 3
		} finally {
			$db.Dispose()
		}
	}

	It 'bulk-loads every user hash on a server when userSid is null (triage path)' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$cachePath = Join-Path $TestDrive 'verified_bulk.sqlite3'
		$db = Open-TboCacheDbReflected -CachePath $cachePath
		try {
			$machineId = Invoke-UpsertMachine -Db $db -ServerName 'bulk01'

			foreach ($i in 1..3) {
				Invoke-UpsertVerifiedPasswordHash -Db $db -MachineId $machineId -ServerName 'bulk01' `
					-UserSid "S-1-5-21-5-5-5-100$i" -UserName "user$i" -HashType 'sha1_pwd' `
					-HashValueHex ('A' * 40 + "0$i").Substring(0, 40) `
					-VerifiedByCmdlet 'Get-TBODpapiCredHist' -VerifiedVia 'credhist_chain_decrypt' | Out-Null
			}

			# Also seed a different server so we can verify server_name filtering works.
			$otherMachineId = Invoke-UpsertMachine -Db $db -ServerName 'otherhost'
			Invoke-UpsertVerifiedPasswordHash -Db $db -MachineId $otherMachineId -ServerName 'otherhost' `
				-UserSid 'S-1-5-21-5-5-5-1001' -UserName 'user1' -HashType 'sha1_pwd' `
				-HashValueHex '9999999999999999999999999999999999999999' `
				-VerifiedByCmdlet 'Get-TBODpapiCredHist' -VerifiedVia 'credhist_chain_decrypt' | Out-Null

			# Bulk query (null SID) must return all three for 'bulk01' and none from 'otherhost'.
			$bulk = Invoke-QueryVerifiedPasswordHashes -Db $db -ServerName 'bulk01' -UserSid $null
			$bulk.Count | Should -Be 3
			($bulk | ForEach-Object { $_.ServerName } | Sort-Object -Unique) | Should -Be 'bulk01'
		} finally {
			$db.Dispose()
		}
	}

	It 'rejects whitespace/empty required arguments' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$cachePath = Join-Path $TestDrive 'verified_reject.sqlite3'
		$db = Open-TboCacheDbReflected -CachePath $cachePath
		try {
			$machineId = Invoke-UpsertMachine -Db $db -ServerName 'reject01'

			# Empty user_sid must throw.
			{ Invoke-UpsertVerifiedPasswordHash -Db $db -MachineId $machineId -ServerName 'reject01' `
					-UserSid '' -UserName 'x' -HashType 'sha1_pwd' -HashValueHex '00' `
					-VerifiedByCmdlet 'Get-TBODpapiCredHist' -VerifiedVia 'credhist_chain_decrypt' } |
				Should -Throw
		} finally {
			$db.Dispose()
		}
	}
}

Describe 'DpapiUserKeyDerivation source-hash metadata (TBO-7xo)' {
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

		# Avoid bracket type literals — see the equivalent note in the TboCacheDatabase Describe above.
		if ($script:moduleAvailable) {
			$module = Get-Module -Name 'Titanis.TBO.Smb2.PowerShell'
			$assembly = $module.ImplementingAssembly
			$script:derivationType = $assembly.GetType('Titanis.Tbo.Smb2.PowerShell.DpapiUserKeyDerivation')
		}
	}

	It 'populates SourceHashType and SourceHash on candidates produced from a plaintext password' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$deriveMethod = $script:derivationType.GetMethod(
			'DerivePreKeyCandidates',
			[System.Reflection.BindingFlags]::Static -bor [System.Reflection.BindingFlags]::NonPublic)

		$candidates = $deriveMethod.Invoke($null, @('S-1-5-21-1-2-3-1001', 'P@ssw0rd!', $null))
		$candidates.Count | Should -BeGreaterThan 0

		foreach ($c in $candidates) {
			$c.SourceHashType | Should -Not -BeNullOrEmpty
			$c.SourceHash | Should -Not -BeNullOrEmpty
			@('sha1_pwd', 'nt_pwd') | Should -Contain $c.SourceHashType
		}

		# At least one candidate should be backed by each source hash type (plaintext produces both).
		($candidates | Where-Object { $_.SourceHashType -eq 'sha1_pwd' } | Measure-Object).Count | Should -BeGreaterThan 0
		($candidates | Where-Object { $_.SourceHashType -eq 'nt_pwd' } | Measure-Object).Count | Should -BeGreaterThan 0
	}

	It 'DerivePreKeyCandidatesFromHashes accepts pre-computed hashes and tags candidates' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$deriveFromHashes = $script:derivationType.GetMethod(
			'DerivePreKeyCandidatesFromHashes',
			[System.Reflection.BindingFlags]::Static -bor [System.Reflection.BindingFlags]::NonPublic)

		# Fake 20-byte SHA-1 and 16-byte NT hash.
		$sha1 = [byte[]](1..20)
		$nt = [byte[]](1..16)

		$candidates = $deriveFromHashes.Invoke($null, @('S-1-5-21-1-2-3-1001', $sha1, $nt))
		$candidates.Count | Should -BeGreaterThan 0

		$sha1Candidate = $candidates | Where-Object { $_.SourceHashType -eq 'sha1_pwd' } | Select-Object -First 1
		$sha1Candidate | Should -Not -BeNullOrEmpty
		# Round-trip check: the candidate's SourceHash should match the input bytes.
		[Convert]::ToHexString($sha1Candidate.SourceHash) | Should -Be ([Convert]::ToHexString($sha1))

		$ntCandidate = $candidates | Where-Object { $_.SourceHashType -eq 'nt_pwd' } | Select-Object -First 1
		$ntCandidate | Should -Not -BeNullOrEmpty
		[Convert]::ToHexString($ntCandidate.SourceHash) | Should -Be ([Convert]::ToHexString($nt))

		# Local-account NT-hash fallback candidate should be present.
		$localNtCandidate = $candidates |
			Where-Object { $_.Label -like '*SHA1(NT)*' -and $_.SourceHashType -eq 'nt_pwd' } |
			Select-Object -First 1
		$localNtCandidate | Should -Not -BeNullOrEmpty
	}
}
