Set-StrictMode -Version Latest

$script:testHarnessPath = Join-Path $PSScriptRoot 'TboTestHarness.ps1'
if (Test-Path -LiteralPath $script:testHarnessPath) {
	. $script:testHarnessPath
}

Describe 'TBO scheduled task cmdlets (mocked)' {
	BeforeAll {
		$testHarnessPath = Join-Path $PSScriptRoot 'TboTestHarness.ps1'
		if (Test-Path -LiteralPath $testHarnessPath) {
			. $testHarnessPath
		}

		function script:Invoke-WithMockProvider {
			param(
				[Parameter(Mandatory = $true)]
				[object]$ProviderInfo,
				[Parameter(Mandatory = $true)]
				[scriptblock]$ScriptBlock
			)

			$scope = Use-TboProviderInfoOverride -ProviderInfo $ProviderInfo
			try {
				& $ScriptBlock
			} finally {
				$scope.Dispose()
			}
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
	}

	It 'Set-TBOScheduledTaskSecurityDescriptor writes TaskCache SD value to fake registry store' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		# SecurityDescriptor sample from service SD tests; valid self-relative binary SD.
		$sdBase64 = @'
AQAUgAwBAAAYAQAAFAAAAEgAAAACADQAAgAAAAKAFAD/AQ8AAQEAAAAAAAEAAAAAFAAYAJ0BAgABAgAAAAAAEwACAAAABgAAAgDEAAcAAAAAABgAnQECAAECAAAAAAAFIAAAACECAAAAABQAnQECAAEBAAAAAAAFEgAAAAAAGACdAQIAAQIAAAAAAAUgAAAAIAIAAAAAFACdAQIAAQEAAAAAAAUEAAAAAAAUAJ0BAgABAQAAAAAABQYAAAAAACgA/wEPAAEGAAAAAAAFUAAAAL9VCHI74CjQiXlL+JGJbnxAJez0AAAoAP8BDwABBgAAAAAABVAAAACcLNIBSon7eJu+XdtzpkmLiIw0HwEBAAAAAAAFEgAAAAEBAAAAAAAFEgAAAA==
'@ -replace '\s', ''
		$sdBytes = [Convert]::FromBase64String($sdBase64)

		$taskKeyPath = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\TBO\TestTask'
		$store = [Titanis.Tbo.Smb2.PowerShell.FakeRegistryStore]::new()
		$store.AddKey($taskKeyPath) | Out-Null

		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRegistrySession { param($serverName, $token) $store.CreateSession() }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Set-TBOScheduledTaskSecurityDescriptor -ServerName 'server' -Path '\TBO\TestTask' -SecurityDescriptor $sdBytes -Confirm:$false

			$value = Get-TBORegValue -ServerName 'server' -Path $taskKeyPath -Name 'SD'
			$value | Should -Not -BeNullOrEmpty
			$registryValueType = Get-TboReferencedType -TypeName 'Titanis.Winterop.Registry.RegistryValueType' -RepoRoot $script:repoRoot
			$value.ValueType | Should -Be ([System.Enum]::Parse($registryValueType, 'Binary'))
			[Convert]::ToBase64String($value.Bytes) | Should -Be ([Convert]::ToBase64String($sdBytes))
		}
	}
}
