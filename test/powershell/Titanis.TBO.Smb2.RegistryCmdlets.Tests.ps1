Set-StrictMode -Version Latest

$script:testHarnessPath = Join-Path $PSScriptRoot 'TboTestHarness.ps1'
if (Test-Path -LiteralPath $script:testHarnessPath) {
	. $script:testHarnessPath
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

function Invoke-WithMockProvider {
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

Describe 'TBO registry cmdlets (mocked)' {
	It 'Get-TBORegSessions -ResolveSid fails before connecting' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:sessionCalled = $false
		$emptySessionTask = [System.Threading.Tasks.Task[Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]]::FromResult($null)
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRemoteRegistrySessionAsync { param($serverName, $token) $script:sessionCalled = $true; $emptySessionTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			{ Get-TBORegSessions -ServerName 'server' -ResolveSid } | Should -Throw -ErrorType ([System.NotSupportedException])
		}

		$script:sessionCalled | Should -BeFalse
	}

	It 'Get-TBORegKey rejects unsupported root keys before connecting' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:sessionCalled = $false
		$emptySessionTask = [System.Threading.Tasks.Task[Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]]::FromResult($null)
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRemoteRegistrySessionAsync { param($serverName, $token) $script:sessionCalled = $true; $emptySessionTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			{ Get-TBORegKey -ServerName 'server' -Path 'HKQQ\\Software' } | Should -Throw -ErrorType ([System.ArgumentException])
		}

		$script:sessionCalled | Should -BeFalse
	}

	It 'New-TBORegKey rejects root key creation before connecting' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:sessionCalled = $false
		$emptySessionTask = [System.Threading.Tasks.Task[Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]]::FromResult($null)
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRemoteRegistrySessionAsync { param($serverName, $token) $script:sessionCalled = $true; $emptySessionTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			{ New-TBORegKey -ServerName 'server' -Path 'HKLM' } | Should -Throw -ErrorType ([System.InvalidOperationException])
		}

		$script:sessionCalled | Should -BeFalse
	}

	It 'Remove-TBORegKey rejects root key removal before connecting' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:sessionCalled = $false
		$emptySessionTask = [System.Threading.Tasks.Task[Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]]::FromResult($null)
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRemoteRegistrySessionAsync { param($serverName, $token) $script:sessionCalled = $true; $emptySessionTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			{ Remove-TBORegKey -ServerName 'server' -Path 'HKLM' } | Should -Throw -ErrorType ([System.InvalidOperationException])
		}

		$script:sessionCalled | Should -BeFalse
	}

	It 'Get-TBORegValue rejects UNC paths before connecting' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:sessionCalled = $false
		$emptySessionTask = [System.Threading.Tasks.Task[Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]]::FromResult($null)
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRemoteRegistrySessionAsync { param($serverName, $token) $script:sessionCalled = $true; $emptySessionTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			{ Get-TBORegValue -ServerName 'server' -Path '\\\\server\\share' } | Should -Throw -ErrorType ([System.ArgumentException])
		}

		$script:sessionCalled | Should -BeFalse
	}

	It 'Get-TBORegChildItem rejects unsupported root keys before connecting' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:sessionCalled = $false
		$emptySessionTask = [System.Threading.Tasks.Task[Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]]::FromResult($null)
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRemoteRegistrySessionAsync { param($serverName, $token) $script:sessionCalled = $true; $emptySessionTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			{ Get-TBORegChildItem -ServerName 'server' -Path 'HKQQ' } | Should -Throw -ErrorType ([System.ArgumentException])
		}

		$script:sessionCalled | Should -BeFalse
	}

	It 'Set-TBORegValue rejects unsupported value types before connecting' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:sessionCalled = $false
		$emptySessionTask = [System.Threading.Tasks.Task[Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]]::FromResult($null)
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRemoteRegistrySessionAsync { param($serverName, $token) $script:sessionCalled = $true; $emptySessionTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			{ Set-TBORegValue -ServerName 'server' -Path 'HKLM\\Software' -Name 'Foo' -Value @{ A = 1 } } | Should -Throw -ErrorType ([System.ArgumentException])
		}

		$script:sessionCalled | Should -BeFalse
	}
}
