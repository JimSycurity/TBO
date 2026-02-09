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
		$export.schemaVersion | Should -Be 2

		$export.machines.Count | Should -Be 1
		$export.principals.Count | Should -Be 1
		$export.credentials.Count | Should -Be 1
		$export.observations.Count | Should -Be 1

		$export.machines[0].serverName | Should -Be 'host1'
		$export.principals[0].sid | Should -Be 'S-1-5-18'
		$export.credentials[0].kind | Should -Be 'NTHash'
		$export.credentials[0].identifier | Should -Be '8846f7eaee8fb117ad06bdd830b7586c'
		$export.observations[0].sourceKind | Should -Be 'Test'
	}
}

