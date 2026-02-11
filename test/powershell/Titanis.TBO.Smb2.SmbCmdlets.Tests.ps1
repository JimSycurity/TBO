Set-StrictMode -Version Latest

$script:testHarnessPath = Join-Path $PSScriptRoot 'TboTestHarness.ps1'
if (Test-Path -LiteralPath $script:testHarnessPath) {
	. $script:testHarnessPath
}

Describe 'TBO SMB cmdlets (mocked)' {
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

	It 'Set-TBOConnectOptions sets server-specific parameters' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:captured = $null
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-GetConnectParametersFor { param($serverName, $defaultIfNone) $null } `
			-SetConnectParameters { param($serverName, $parameters) $script:captured = @{ Server = $serverName; Parameters = $parameters } }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Set-TBOConnectOptions -ServerName 'fileserver'
		}

		$script:captured.Server | Should -Be 'fileserver'
		$script:captured.Parameters | Should -Not -BeNullOrEmpty
		$script:captured.Parameters.GetType().Name | Should -Be 'SmbConnectionParameters'
	}

	It 'Set-TBOConnectOptions captures Socks5Proxy when provided' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:captured = $null
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-GetConnectParametersFor { param($serverName, $defaultIfNone) $null } `
			-SetConnectParameters { param($serverName, $parameters) $script:captured = @{ Server = $serverName; Parameters = $parameters } }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Set-TBOConnectOptions -ServerName 'fileserver' -Socks5Proxy '127.0.0.1:1080'
		}

		$script:captured.Server | Should -Be 'fileserver'
		$script:captured.Parameters.Socks5Proxy | Should -Be '127.0.0.1:1080'
	}

	It 'Set-TBOConnectOptions merges onto existing per-server parameters' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:captured = $null
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot
		$existing = $mock.DefaultConnectParameters
		$existing.IncludeRootReparseInfo = $true
		$existing.UserName = 'existing'

		$mock.GetConnectParametersForFunc = [Func[string, bool, object]]{
			param($serverName, $defaultIfNone)
			$existing
		}
		$mock.SetConnectParametersAction = [Action[string, object]]{
			param($serverName, $parameters)
			$script:captured = $parameters
		}

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Set-TBOConnectOptions -ServerName 'fileserver' -UserName 'newuser'
		}

		$script:captured.UserName | Should -Be 'newuser'
		$script:captured.IncludeRootReparseInfo | Should -BeTrue
	}

	It 'Set-TBOConnectOptions updates default parameters when no server is specified' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot
		$existing = $mock.DefaultConnectParameters
		$existing.IncludeRootReparseInfo = $true

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Set-TBOConnectOptions -UserName 'defaultuser'
		}

		$mock.DefaultConnectParameters | Should -Not -BeNullOrEmpty
		$mock.DefaultConnectParameters.GetType().Name | Should -Be 'SmbConnectionParameters'
		$mock.DefaultConnectParameters.UserName | Should -Be 'defaultuser'
		$mock.DefaultConnectParameters.IncludeRootReparseInfo | Should -BeTrue
	}

	It 'Disconnect-TBOSmbServer -All calls DisconnectAllAsync only' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:disconnectAllCalled = $false
		$script:disconnectServerCalled = $false
		$script:capturedForce = $null
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-DisconnectAllAsync { param($force) $script:disconnectAllCalled = $true; $script:capturedForce = $force; [System.Threading.Tasks.Task]::CompletedTask } `
			-DisconnectServerAsync { param($serverName, $port, $force) $script:disconnectServerCalled = $true; [System.Threading.Tasks.Task]::CompletedTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Disconnect-TBOSmbServer -All
		}

		$script:disconnectAllCalled | Should -BeTrue
		$script:disconnectServerCalled | Should -BeFalse
		$script:capturedForce | Should -BeFalse
	}

	It 'Disconnect-TBOSmbServer uses server name and port when provided' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:capturedServer = $null
		$script:capturedPort = $null
		$script:capturedForce = $null
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-DisconnectServerAsync { param($serverName, $port, $force) $script:capturedServer = $serverName; $script:capturedPort = $port; $script:capturedForce = $force; [System.Threading.Tasks.Task]::CompletedTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Disconnect-TBOSmbServer -ServerName 'fileserver' -RemotePort 445
		}

		$script:capturedServer | Should -Be 'fileserver'
		$script:capturedPort | Should -Be 445
		$script:capturedForce | Should -BeFalse
	}

	It 'Disconnect-TBOSmbServer -All -Force passes force to disconnect' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:capturedForce = $null
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-DisconnectAllAsync { param($force) $script:capturedForce = $force; [System.Threading.Tasks.Task]::CompletedTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Disconnect-TBOSmbServer -All -Force
		}

		$script:capturedForce | Should -BeTrue
	}

	It 'Disconnect-TBOSmbServer -Force passes force to disconnect' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:capturedForce = $null
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-DisconnectServerAsync { param($serverName, $port, $force) $script:capturedForce = $force; [System.Threading.Tasks.Task]::CompletedTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Disconnect-TBOSmbServer -ServerName 'fileserver' -Force
		}

		$script:capturedForce | Should -BeTrue
	}

	It 'Get-TBOSmbSessions validates ServerName before connecting' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:sessionCalled = $false
		$emptySessionTask = [System.Threading.Tasks.Task[Titanis.Tbo.Smb2.PowerShell.ServerServiceSession]]::FromResult([Titanis.Tbo.Smb2.PowerShell.ServerServiceSession]$null)
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenServerServiceSessionAsync { param($serverName, $token) $script:sessionCalled = $true; $emptySessionTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Should -Throw -ExceptionType ([System.ArgumentException]) -ActualValue { Get-TBOSmbSessions -ServerName ' ' }
		}

		$script:sessionCalled | Should -BeFalse
	}

	It 'Get-TBOSmbShares validates ServerName before connecting' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:sessionCalled = $false
		$emptySessionTask = [System.Threading.Tasks.Task[Titanis.Tbo.Smb2.PowerShell.ServerServiceSession]]::FromResult([Titanis.Tbo.Smb2.PowerShell.ServerServiceSession]$null)
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenServerServiceSessionAsync { param($serverName, $token) $script:sessionCalled = $true; $emptySessionTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Should -Throw -ExceptionType ([System.Management.Automation.ParameterBindingException]) -ActualValue { Get-TBOSmbShares -ServerName '' }
		}

		$script:sessionCalled | Should -BeFalse
	}

	It 'Get-TBOSmbOpenFiles validates ServerName before connecting' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:sessionCalled = $false
		$emptySessionTask = [System.Threading.Tasks.Task[Titanis.Tbo.Smb2.PowerShell.ServerServiceSession]]::FromResult([Titanis.Tbo.Smb2.PowerShell.ServerServiceSession]$null)
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenServerServiceSessionAsync { param($serverName, $token) $script:sessionCalled = $true; $emptySessionTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Should -Throw -ExceptionType ([System.ArgumentException]) -ActualValue { Get-TBOSmbOpenFiles -ServerName ' ' }
		}

		$script:sessionCalled | Should -BeFalse
	}

	It 'Get-TBOSmbNics validates path input' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot
		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Should -Throw -ExceptionType ([System.ArgumentException]) -ActualValue { Get-TBOSmbNics -Path ' ' }
		}
	}

	It 'Get-TBOSmbSnapshots validates path input' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot
		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Should -Throw -ExceptionType ([System.ArgumentException]) -ActualValue { Get-TBOSmbSnapshots -Path ' ' }
		}
	}

	It 'Get-TBOSmbStreams requires a share name' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot
		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Should -Throw -ExceptionType ([System.ArgumentException]) -ActualValue { Get-TBOSmbStreams -Path '\\server' }
		}
	}

	It 'Watch-TBOSmb requires a share name' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot
		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Should -Throw -ExceptionType ([System.ArgumentException]) -ActualValue { Watch-TBOSmb -Path '\\server' }
		}
	}
}
