Set-StrictMode -Version Latest

$script:testHarnessPath = Join-Path $PSScriptRoot 'TboTestHarness.ps1'
if (Test-Path -LiteralPath $script:testHarnessPath) {
	. $script:testHarnessPath
}

Describe 'TBO registry cmdlets (mocked)' {
	BeforeAll {
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
	}

	It 'Get-TBORegSessions -ResolveSid fails before connecting' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:sessionCalled = $false
		$emptySessionTask = [System.Threading.Tasks.Task[Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]]::FromResult([Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]$null)
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRemoteRegistrySessionAsync { param($serverName, $token) $script:sessionCalled = $true; $emptySessionTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Should -Throw -ExceptionType ([System.NotSupportedException]) -ActualValue { Get-TBORegSessions -ServerName 'server' -ResolveSid }
		}

		$script:sessionCalled | Should -BeFalse
	}

	It 'Get-TBORegKey rejects unsupported root keys before connecting' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:sessionCalled = $false
		$emptySessionTask = [System.Threading.Tasks.Task[Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]]::FromResult([Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]$null)
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRemoteRegistrySessionAsync { param($serverName, $token) $script:sessionCalled = $true; $emptySessionTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Should -Throw -ExceptionType ([System.ArgumentException]) -ActualValue { Get-TBORegKey -ServerName 'server' -Path 'HKQQ\\Software' }
		}

		$script:sessionCalled | Should -BeFalse
	}

	It 'New-TBORegKey rejects root key creation before connecting' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:sessionCalled = $false
		$emptySessionTask = [System.Threading.Tasks.Task[Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]]::FromResult([Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]$null)
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRemoteRegistrySessionAsync { param($serverName, $token) $script:sessionCalled = $true; $emptySessionTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Should -Throw -ExceptionType ([System.InvalidOperationException]) -ActualValue { New-TBORegKey -ServerName 'server' -Path 'HKLM' }
		}

		$script:sessionCalled | Should -BeFalse
	}

	It 'Remove-TBORegKey rejects root key removal before connecting' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:sessionCalled = $false
		$emptySessionTask = [System.Threading.Tasks.Task[Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]]::FromResult([Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]$null)
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRemoteRegistrySessionAsync { param($serverName, $token) $script:sessionCalled = $true; $emptySessionTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Should -Throw -ExceptionType ([System.InvalidOperationException]) -ActualValue { Remove-TBORegKey -ServerName 'server' -Path 'HKLM' }
		}

		$script:sessionCalled | Should -BeFalse
	}

	It 'Get-TBORegValue rejects UNC paths before connecting' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:sessionCalled = $false
		$emptySessionTask = [System.Threading.Tasks.Task[Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]]::FromResult([Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]$null)
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRemoteRegistrySessionAsync { param($serverName, $token) $script:sessionCalled = $true; $emptySessionTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Should -Throw -ExceptionType ([System.ArgumentException]) -ActualValue { Get-TBORegValue -ServerName 'server' -Path '\\\\server\\share' }
		}

		$script:sessionCalled | Should -BeFalse
	}

	It 'Get-TBORegChildItem rejects unsupported root keys before connecting' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:sessionCalled = $false
		$emptySessionTask = [System.Threading.Tasks.Task[Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]]::FromResult([Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]$null)
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRemoteRegistrySessionAsync { param($serverName, $token) $script:sessionCalled = $true; $emptySessionTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Should -Throw -ExceptionType ([System.ArgumentException]) -ActualValue { Get-TBORegChildItem -ServerName 'server' -Path 'HKQQ' }
		}

		$script:sessionCalled | Should -BeFalse
	}

	It 'Set-TBORegValue rejects unsupported value types before connecting' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:sessionCalled = $false
		$emptySessionTask = [System.Threading.Tasks.Task[Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]]::FromResult([Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]$null)
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRemoteRegistrySessionAsync { param($serverName, $token) $script:sessionCalled = $true; $emptySessionTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Should -Throw -ExceptionType ([System.ArgumentException]) -ActualValue { Set-TBORegValue -ServerName 'server' -Path 'HKLM\\Software' -Name 'Foo' -Value @{ A = 1 } }
		}

		$script:sessionCalled | Should -BeFalse
	}
}
