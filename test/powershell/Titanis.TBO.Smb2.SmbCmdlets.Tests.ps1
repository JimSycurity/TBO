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

Describe 'TBO SMB cmdlets (mocked)' {
	It 'Set-TBOSmbConnectOptions sets server-specific parameters' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:captured = $null
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-GetConnectParametersFor { param($serverName, $defaultIfNone) $null } `
			-SetConnectParameters { param($serverName, $parameters) $script:captured = @{ Server = $serverName; Parameters = $parameters } }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Set-TBOSmbConnectOptions -ServerName 'fileserver'
		}

		$script:captured.Server | Should -Be 'fileserver'
		$script:captured.Parameters | Should -Not -BeNullOrEmpty
		$script:captured.Parameters.GetType().Name | Should -Be 'SmbConnectionParameters'
	}

	It 'Set-TBOSmbConnectOptions updates default parameters when no server is specified' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Set-TBOSmbConnectOptions
		}

		$mock.DefaultConnectParameters | Should -Not -BeNullOrEmpty
		$mock.DefaultConnectParameters.GetType().Name | Should -Be 'SmbConnectionParameters'
	}

	It 'Disconnect-TBOSmbServer -All calls DisconnectAllAsync only' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:disconnectAllCalled = $false
		$script:disconnectServerCalled = $false
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-DisconnectAllAsync { $script:disconnectAllCalled = $true; [System.Threading.Tasks.Task]::CompletedTask } `
			-DisconnectServerAsync { param($serverName, $port) $script:disconnectServerCalled = $true; [System.Threading.Tasks.Task]::CompletedTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Disconnect-TBOSmbServer -All
		}

		$script:disconnectAllCalled | Should -BeTrue
		$script:disconnectServerCalled | Should -BeFalse
	}

	It 'Disconnect-TBOSmbServer uses server name and port when provided' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:capturedServer = $null
		$script:capturedPort = $null
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-DisconnectServerAsync { param($serverName, $port) $script:capturedServer = $serverName; $script:capturedPort = $port; [System.Threading.Tasks.Task]::CompletedTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Disconnect-TBOSmbServer -ServerName 'fileserver' -RemotePort 445
		}

		$script:capturedServer | Should -Be 'fileserver'
		$script:capturedPort | Should -Be 445
	}

	It 'Get-TBOSmbSessions validates ServerName before connecting' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:sessionCalled = $false
		$emptySessionTask = [System.Threading.Tasks.Task[Titanis.Tbo.Smb2.PowerShell.ServerServiceSession]]::FromResult($null)
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenServerServiceSessionAsync { param($serverName, $token) $script:sessionCalled = $true; $emptySessionTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			{ Get-TBOSmbSessions -ServerName ' ' } | Should -Throw -ErrorType ([System.ArgumentException])
		}

		$script:sessionCalled | Should -BeFalse
	}

	It 'Get-TBOSmbShares validates ServerName before connecting' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:sessionCalled = $false
		$emptySessionTask = [System.Threading.Tasks.Task[Titanis.Tbo.Smb2.PowerShell.ServerServiceSession]]::FromResult($null)
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenServerServiceSessionAsync { param($serverName, $token) $script:sessionCalled = $true; $emptySessionTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			{ Get-TBOSmbShares -ServerName '' } | Should -Throw -ErrorType ([System.ArgumentException])
		}

		$script:sessionCalled | Should -BeFalse
	}

	It 'Get-TBOSmbOpenFiles validates ServerName before connecting' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:sessionCalled = $false
		$emptySessionTask = [System.Threading.Tasks.Task[Titanis.Tbo.Smb2.PowerShell.ServerServiceSession]]::FromResult($null)
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenServerServiceSessionAsync { param($serverName, $token) $script:sessionCalled = $true; $emptySessionTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			{ Get-TBOSmbOpenFiles -ServerName ' ' } | Should -Throw -ErrorType ([System.ArgumentException])
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
			{ Get-TBOSmbNics -Path ' ' } | Should -Throw -ErrorType ([System.ArgumentException])
		}
	}

	It 'Get-TBOSmbSnapshots validates path input' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot
		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			{ Get-TBOSmbSnapshots -Path ' ' } | Should -Throw -ErrorType ([System.ArgumentException])
		}
	}

	It 'Get-TBOSmbStreams requires a share name' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot
		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			{ Get-TBOSmbStreams -Path '\\server' } | Should -Throw -ErrorType ([System.ArgumentException])
		}
	}

	It 'Watch-TBOSmb requires a share name' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot
		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			{ Watch-TBOSmb -Path '\\server' } | Should -Throw -ErrorType ([System.ArgumentException])
		}
	}
}
