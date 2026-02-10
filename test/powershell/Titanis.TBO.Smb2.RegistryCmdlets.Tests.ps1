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

	It 'Get-TBORegServices rejects conflicting security descriptor formats before connecting' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:sessionCalled = $false
		$emptySessionTask = [System.Threading.Tasks.Task[Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]]::FromResult([Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]$null)
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRemoteRegistrySessionAsync { param($serverName, $token) $script:sessionCalled = $true; $emptySessionTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Should -Throw -ExceptionType ([System.ArgumentException]) -ActualValue { Get-TBORegServices -ServerName 'server' -AsSddl -AsWindows }
		}

		$script:sessionCalled | Should -BeFalse
	}

	It 'Get-TBORegServices rejects unsupported root keys before connecting' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:sessionCalled = $false
		$emptySessionTask = [System.Threading.Tasks.Task[Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]]::FromResult([Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]$null)
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRemoteRegistrySessionAsync { param($serverName, $token) $script:sessionCalled = $true; $emptySessionTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Should -Throw -ExceptionType ([System.ArgumentException]) -ActualValue { Get-TBORegServices -ServerName 'server' -Path 'HKQQ\\Software' }
		}

		$script:sessionCalled | Should -BeFalse
	}

	It 'Find-TBORegWeakServices rejects unsupported root keys before connecting' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$script:sessionCalled = $false
		$emptySessionTask = [System.Threading.Tasks.Task[Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]]::FromResult([Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]$null)
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRemoteRegistrySessionAsync { param($serverName, $token) $script:sessionCalled = $true; $emptySessionTask }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Should -Throw -ExceptionType ([System.ArgumentException]) -ActualValue { Find-TBORegWeakServices -ServerName 'server' -Path 'HKQQ\\Software' }
		}

		$script:sessionCalled | Should -BeFalse
	}

	It 'Find-TBORegWeakServices can parse service Security SD bytes that include custom ACEs' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$sdBase64 = @'
AQAUgAwBAAAYAQAAFAAAAEgAAAACADQAAgAAAAKAFAD/AQ8AAQEAAAAAAAEAAAAAFAAYAJ0BAgABAgAAAAAAEwACAAAABgAAAgDEAAcAAAAAABgAnQECAAECAAAAAAAFIAAAACECAAAAABQAnQECAAEBAAAAAAAFEgAAAAAAGACdAQIAAQIAAAAAAAUgAAAAIAIAAAAAFACdAQIAAQEAAAAAAAUEAAAAAAAUAJ0BAgABAQAAAAAABQYAAAAAACgA/wEPAAEGAAAAAAAFUAAAAL9VCHI74CjQiXlL+JGJbnxAJez0AAAoAP8BDwABBgAAAAAABVAAAACcLNIBSon7eJu+XdtzpkmLiIw0HwEBAAAAAAAFEgAAAAEBAAAAAAAFEgAAAA==
'@ -replace '\s', ''
		$sdBytes = [Convert]::FromBase64String($sdBase64)

		$store = [Titanis.Tbo.Smb2.PowerShell.FakeRegistryStore]::new()
		$store.AddKey('HKLM\SYSTEM\CurrentControlSet\Services\MDCoreSvc') | Out-Null
		$store.AddKey('HKLM\SYSTEM\CurrentControlSet\Services\MDCoreSvc\Security') | Out-Null
		$store.SetBinaryValue('HKLM\SYSTEM\CurrentControlSet\Services\MDCoreSvc\Security', 'Security', $sdBytes) | Out-Null

		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRegistrySession { param($serverName, $token) $store.CreateSession() }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			$warnings = @()
			{ Find-TBORegWeakServices -ServerName 'server' -Name 'MDCoreSvc' -WarningVariable warnings -WarningAction Continue | Out-Null } | Should -Not -Throw
			$warnings.Count | Should -Be 0
		}
	}

	It 'Get-TBORegValue reads from fake registry store' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$store = [Titanis.Tbo.Smb2.PowerShell.FakeRegistryStore]::new()
		$store.AddKey('HKLM\Software\Titanis', 'TitanisClass') | Out-Null
		$store.SetStringValue('HKLM\Software\Titanis', 'Path', 'C:\Temp') | Out-Null
		$store.SetDwordValue('HKLM\Software\Titanis', 'Enabled', 1) | Out-Null

		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRegistrySession { param($serverName, $token) $store.CreateSession() }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			$keyInfo = Get-TBORegKey -ServerName 'server' -Path 'HKLM\Software\Titanis' -IncludeClass
			$keyInfo.ClassName | Should -Be 'TitanisClass'
			$keyInfo.ValueCount | Should -Be 2

			$value = Get-TBORegValue -ServerName 'server' -Path 'HKLM\Software\Titanis' -Name 'Path'
			$value.Value | Should -Be 'C:\Temp'
		}
	}

	It 'Set-TBORegValue writes to fake registry store' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$store = [Titanis.Tbo.Smb2.PowerShell.FakeRegistryStore]::new()
		$store.AddKey('HKLM\Software\Titanis') | Out-Null

		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRegistrySession { param($serverName, $token) $store.CreateSession() }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Set-TBORegValue -ServerName 'server' -Path 'HKLM\Software\Titanis' -Name 'Answer' -Value 42
			$value = Get-TBORegValue -ServerName 'server' -Path 'HKLM\Software\Titanis' -Name 'Answer'
			$value.Value | Should -Be 42
		}
	}

	It 'Get-TBOEnvironmentVariable reads machine env vars from fake registry store' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$store = [Titanis.Tbo.Smb2.PowerShell.FakeRegistryStore]::new()
		$store.AddKey('HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment') | Out-Null
		$store.SetStringValue('HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', 'C:\Temp') | Out-Null

		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRegistrySession { param($serverName, $token) $store.CreateSession() }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			$var = Get-TBOEnvironmentVariable -ServerName 'server' -Name Path
			$var.Name | Should -Be 'Path'
			$var.Value | Should -Be 'C:\Temp'
			$var.Scope | Should -Be 'Machine'
		}
	}

	It 'Set-TBOEnvironmentVariable writes ExpandString when -Expand is specified' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$store = [Titanis.Tbo.Smb2.PowerShell.FakeRegistryStore]::new()
		$store.AddKey('HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment') | Out-Null

		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRegistrySession { param($serverName, $token) $store.CreateSession() }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Set-TBOEnvironmentVariable -ServerName 'server' -Name Path -Value '%Path%;C:\Temp' -Expand
			$var = Get-TBOEnvironmentVariable -ServerName 'server' -Name Path
			$var.ValueType | Should -Be ([Titanis.Msrpc.Msrrp.RegistryValueType]::ExpandString)
			$var.Value | Should -Be '%Path%;C:\Temp'
		}
	}

	It 'Set-TBOEnvironmentVariable -Scope User writes to HKU SID environment key' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

			$sid = 'S-1-5-21-1-2-3-4'
			$store = [Titanis.Tbo.Smb2.PowerShell.FakeRegistryStore]::new()
				$store.AddKey("HKU\$sid\Environment") | Out-Null

		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRegistrySession { param($serverName, $token) $store.CreateSession() }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Set-TBOEnvironmentVariable -ServerName 'server' -Scope User -UserSid $sid -Name DOTNET_STARTUP_HOOKS -Value 'C:\hook.dll'
			$var = Get-TBOEnvironmentVariable -ServerName 'server' -Scope User -UserSid $sid -Name DOTNET_STARTUP_HOOKS
			$var.Value | Should -Be 'C:\hook.dll'
			$var.Scope | Should -Be 'User'
			$var.UserSid | Should -Be $sid
		}
	}

	It 'Remove-TBOEnvironmentVariable deletes from fake registry store' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$store = [Titanis.Tbo.Smb2.PowerShell.FakeRegistryStore]::new()
		$store.AddKey('HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment') | Out-Null
		$store.SetStringValue('HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'DOTNET_STARTUP_HOOKS', 'C:\hook.dll') | Out-Null

		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRegistrySession { param($serverName, $token) $store.CreateSession() }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Remove-TBOEnvironmentVariable -ServerName 'server' -Name DOTNET_STARTUP_HOOKS -Confirm:$false
			{ Get-TBOEnvironmentVariable -ServerName 'server' -Name DOTNET_STARTUP_HOOKS } | Should -Throw
		}
	}
}

Describe 'Registry retry helper (mocked)' {
	BeforeAll {
		$testHarnessPath = Join-Path $PSScriptRoot 'TboTestHarness.ps1'
		if (Test-Path -LiteralPath $testHarnessPath) {
			. $testHarnessPath
		}

		if (-not $script:repoRoot) {
			$script:repoRoot = Get-TboRepoRoot -Paths @($PSScriptRoot, (Get-Location).Path)
		}

		if (-not $script:moduleAvailable) {
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
	}
	It 'uses OpenRegistrySession when provided' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$store = [Titanis.Tbo.Smb2.PowerShell.FakeRegistryStore]::new()
		$store.AddKey('HKLM\Software\Titanis') | Out-Null

		$script:remoteCalled = $false
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRegistrySession { param($serverName, $token) $store.CreateSession() } `
			-OpenRemoteRegistrySessionAsync { param($serverName, $token) $script:remoteCalled = $true; throw 'OpenRemoteRegistrySessionAsync should not be called.' }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			Get-TBORegKey -ServerName 'server' -Path 'HKLM\Software\Titanis' | Out-Null
		}

		$script:remoteCalled | Should -BeFalse
	}

	It 'invalidates cached session on transport error' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$store = [Titanis.Tbo.Smb2.PowerShell.FakeRegistryStore]::new()
		$session = $store.CreateSession()
		$script:invalidations = 0

		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRegistrySession { param($serverName, $token) $session } `
			-InvalidateRegistrySession { param($serverName, $reason) $script:invalidations++ }

		$helperType = [Titanis.Tbo.Smb2.PowerShell.SmbCmdlet].Assembly.GetType('Titanis.Tbo.Smb2.PowerShell.RegistryRetryHelper')
		$execute = $helperType.GetMethod('Execute', [System.Reflection.BindingFlags]::Static -bor [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Public, $null, @(
			[Titanis.Tbo.Smb2.PowerShell.ISmbProviderInfo],
			[string],
			[System.Threading.CancellationToken],
			[System.Action[Titanis.Tbo.Smb2.PowerShell.IRegistrySession]]
		), $null)

		$action = [System.Action[Titanis.Tbo.Smb2.PowerShell.IRegistrySession]]{
			throw [System.IO.IOException]::new('transport error')
		}

		{ $execute.Invoke($null, @($mock, 'server', [System.Threading.CancellationToken]::None, $action)) } | Should -Throw
		$script:invalidations | Should -BeGreaterThan 0
	}

	It 'recovers after a transport error and continues' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$store = [Titanis.Tbo.Smb2.PowerShell.FakeRegistryStore]::new()
		$session = $store.CreateSession()
		$script:invalidations = 0
		$script:attempt = 0

		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRegistrySession { param($serverName, $token) $session } `
			-InvalidateRegistrySession { param($serverName, $reason) $script:invalidations++ }

		$helperType = [Titanis.Tbo.Smb2.PowerShell.SmbCmdlet].Assembly.GetType('Titanis.Tbo.Smb2.PowerShell.RegistryRetryHelper')
		$execute = $helperType.GetMethod('Execute', [System.Reflection.BindingFlags]::Static -bor [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Public, $null, @(
			[Titanis.Tbo.Smb2.PowerShell.ISmbProviderInfo],
			[string],
			[System.Threading.CancellationToken],
			[System.Action[Titanis.Tbo.Smb2.PowerShell.IRegistrySession]]
		), $null)

		$action = [System.Action[Titanis.Tbo.Smb2.PowerShell.IRegistrySession]]{
			$script:attempt++
			if ($script:attempt -eq 1) {
				throw [System.IO.IOException]::new('transport error')
			}
		}

		{ $execute.Invoke($null, @($mock, 'server', [System.Threading.CancellationToken]::None, $action)) } | Should -Not -Throw
		$script:invalidations | Should -BeGreaterThan 0
		$script:attempt | Should -Be 2
	}
}
