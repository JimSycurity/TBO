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
