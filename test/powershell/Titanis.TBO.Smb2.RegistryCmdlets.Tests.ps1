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

	It 'Get-TBORegSessions -ResolveSid resolves names from registry data with SID fallback' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$sidResolvedFromVolatile = 'S-1-5-21-1-2-3-1001'
		$sidResolvedFromProfile = 'S-1-5-21-1-2-3-1002'
		$sidFallback = 'S-1-5-21-1-2-3-1003'

		$store = [Titanis.Tbo.Smb2.PowerShell.FakeRegistryStore]::new()
		$store.AddKey("HKU\$sidResolvedFromVolatile") | Out-Null
		$store.AddKey("HKU\$sidResolvedFromVolatile\Volatile Environment\1") | Out-Null
		$store.SetStringValue("HKU\$sidResolvedFromVolatile\Volatile Environment\1", 'USERDOMAIN', 'CORP') | Out-Null
		$store.SetStringValue("HKU\$sidResolvedFromVolatile\Volatile Environment\1", 'USERNAME', 'alice') | Out-Null
		$store.AddKey("HKU\$sidResolvedFromProfile") | Out-Null
		$store.AddKey("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sidResolvedFromProfile") | Out-Null
		$store.SetStringValue("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sidResolvedFromProfile", 'ProfileImagePath', 'C:\Users\bob') | Out-Null
		$store.AddKey("HKU\$sidFallback") | Out-Null
		$store.AddKey('HKU\S-1-5-18') | Out-Null

		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRegistrySession { param($serverName, $token) $store.CreateSession() }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			$result = @(Get-TBORegSessions -ServerName 'server' -ResolveSid)
			$result | Should -Contain 'CORP\alice'
			$result | Should -Contain 'bob'
			$result | Should -Contain $sidFallback
			$result | Should -Not -Contain $sidResolvedFromVolatile
			$result | Should -Not -Contain $sidResolvedFromProfile
			$result | Should -Not -Contain 'S-1-5-18'
		}
	}

	It 'Get-TBORegSessions returns raw user SIDs when -ResolveSid is not set' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$store = [Titanis.Tbo.Smb2.PowerShell.FakeRegistryStore]::new()
		$store.AddKey('HKU\S-1-5-21-5-6-7-1001') | Out-Null
		$store.AddKey('HKU\S-1-5-21-5-6-7-1002') | Out-Null
		$store.AddKey('HKU\S-1-5-18') | Out-Null
		$store.AddKey('HKU\S-1-5-21-5-6-7-1002_Classes') | Out-Null

		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRegistrySession { param($serverName, $token) $store.CreateSession() }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			$result = @(Get-TBORegSessions -ServerName 'server')
			$result | Should -Contain 'S-1-5-21-5-6-7-1001'
			$result | Should -Contain 'S-1-5-21-5-6-7-1002'
			$result | Should -Not -Contain 'S-1-5-18'
			$result.Count | Should -Be 2
		}
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

	It 'Get-TBORegServiceDetails includes Parameters and Performance subkey technique values' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		$servicePath = 'HKLM\SYSTEM\CurrentControlSet\Services\SvcTech'
		$parametersPath = "$servicePath\Parameters"
		$performancePath = "$servicePath\Performance"

		$store = [Titanis.Tbo.Smb2.PowerShell.FakeRegistryStore]::new()
		$store.AddKey($servicePath) | Out-Null
		$store.SetStringValue($servicePath, 'ImagePath', 'C:\Windows\System32\svchost.exe -k netsvcs') | Out-Null
		$store.AddKey($parametersPath) | Out-Null
		$store.SetStringValue($parametersPath, 'ServiceDll', 'C:\Windows\System32\example-service.dll') | Out-Null
		$store.SetStringValue($parametersPath, 'ServiceMain', 'ServiceMain') | Out-Null
		$store.SetDwordValue($parametersPath, 'ServiceDllUnloadOnStop', 1) | Out-Null
		$store.AddKey($performancePath) | Out-Null
		$store.SetStringValue($performancePath, 'Library', 'C:\Windows\System32\example-perf.dll') | Out-Null
		$store.SetStringValue($performancePath, 'Open', 'OpenPerfData') | Out-Null
		$store.SetStringValue($performancePath, 'Collect', 'CollectPerfData') | Out-Null
		$store.SetStringValue($performancePath, 'Close', 'ClosePerfData') | Out-Null

		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRegistrySession { param($serverName, $token) $store.CreateSession() }

		Invoke-WithMockProvider -ProviderInfo $mock -ScriptBlock {
			$svc = Get-TBORegServiceDetails -ServerName 'server' -Name 'SvcTech'
			$svc.KeyName | Should -Be 'SvcTech'
			$svc.ServiceDll | Should -Be 'C:\Windows\System32\example-service.dll'
			$svc.ServiceMain | Should -Be 'ServiceMain'
			$svc.ServiceDllUnloadOnStop | Should -Be 'True (1)'
			$svc.PerformanceLibrary | Should -Be 'C:\Windows\System32\example-perf.dll'
			$svc.PerformanceOpen | Should -Be 'OpenPerfData'
			$svc.PerformanceCollect | Should -Be 'CollectPerfData'
			$svc.PerformanceClose | Should -Be 'ClosePerfData'

			$svc.ParametersValues | Should -Not -BeNullOrEmpty
			$svc.PerformanceValues | Should -Not -BeNullOrEmpty
			@($svc.ParametersValues | Where-Object Name -eq 'ServiceDll').Count | Should -Be 1
			@($svc.PerformanceValues | Where-Object Name -eq 'Library').Count | Should -Be 1
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

	It 'routes local server aliases to local registry mode' -TestCases @(
		@{ ServerName = 'localhost' },
		@{ ServerName = '.' },
		@{ ServerName = '127.0.0.1' },
		@{ ServerName = '::1' },
		@{ ServerName = [System.Environment]::MachineName }
	) {
		param($ServerName)

		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		if (-not $ServerName) {
			Set-ItResult -Skipped -Because 'ServerName test case is empty.'
			return
		}

		$script:sessionType = $null
		$mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
			-OpenRegistrySession { param($serverName, $token) throw 'OpenRegistrySession should not be called.' } `
			-OpenRemoteRegistrySessionAsync { param($serverName, $token) throw 'OpenRemoteRegistrySessionAsync should not be called.' }

		$helperType = [Titanis.Tbo.Smb2.PowerShell.SmbCmdlet].Assembly.GetType('Titanis.Tbo.Smb2.PowerShell.RegistryRetryHelper')
		$execute = $helperType.GetMethod('Execute', [System.Reflection.BindingFlags]::Static -bor [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Public, $null, @(
			[Titanis.Tbo.Smb2.PowerShell.ISmbProviderInfo],
			[string],
			[System.Threading.CancellationToken],
			[System.Action[Titanis.Tbo.Smb2.PowerShell.IRegistrySession]]
		), $null)

		$action = [System.Action[Titanis.Tbo.Smb2.PowerShell.IRegistrySession]]{
			param($session)
			$script:sessionType = $session.GetType().FullName
		}

		{ $execute.Invoke($null, @($mock, $ServerName, [System.Threading.CancellationToken]::None, $action)) } | Should -Not -Throw
		$script:sessionType | Should -Match 'LocalRegistrySession'
	}
}

Describe 'TBO.Reg provider (local mode)' {
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

	It 'New-PSDrive -PSProvider TBO.Reg -Root . can browse HKLM/HKCU' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		if (-not $IsWindows) {
			Set-ItResult -Skipped -Because 'Local registry provider tests are Windows-only.'
			return
		}

		$driveName = 'tbo-reg-local-test'
		if (Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue) {
			Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
		}

		try {
			New-PSDrive -Name $driveName -PSProvider 'TBO.Reg' -Root . | Out-Null

			$hives = Get-ChildItem "$driveName`:\"
			($hives | Select-Object -ExpandProperty Name) | Should -Contain 'HKEY_LOCAL_MACHINE'
			($hives | Select-Object -ExpandProperty Name) | Should -Contain 'HKEY_CURRENT_USER'

			{ Get-Item "$driveName`:\HKLM\SOFTWARE" | Out-Null } | Should -Not -Throw
			{ Get-Item "$driveName`:\HKCU\SOFTWARE" | Out-Null } | Should -Not -Throw
		}
		finally {
			Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
		}
	}
}

Describe 'Registry security descriptor local mode' {
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

	It 'handles local SACL operations based on SeSecurityPrivilege state' {
		if (-not $script:moduleAvailable) {
			Set-ItResult -Skipped -Because 'Module not available for cmdlet tests.'
			return
		}

		if (-not $IsWindows) {
			Set-ItResult -Skipped -Because 'Local registry SACL tests are Windows-only.'
			return
		}

		$keyPath = "HKCU\SOFTWARE\TBO-Sacl-Test-$([Guid]::NewGuid().ToString('N'))"
		$created = $false
		try {
			New-TBORegKey -ServerName localhost -Path $keyPath -Confirm:$false | Out-Null
			$created = $true

			$getSaclError = $null
			$saclBytes = $null
			try {
				$saclBytes = Get-TBORegSecurityDescriptor -ServerName localhost -Path $keyPath -Sections Sacl -AsBytes -ErrorAction Stop
			} catch {
				$getSaclError = $_.Exception
			}

			if ($getSaclError) {
				$getSaclError.Message | Should -Match 'SeSecurityPrivilege'

				$setSaclError = $null
				try {
					Set-TBORegSecurityDescriptor -ServerName localhost -Path $keyPath -SecurityDescriptor 'S:(AU;SA;KA;;;WD)' -Sections Sacl -Confirm:$false -ErrorAction Stop
				} catch {
					$setSaclError = $_.Exception
				}

				$setSaclError | Should -Not -BeNullOrEmpty
				$setSaclError.Message | Should -Match 'SeSecurityPrivilege'
				return
			}

			$saclBytes | Should -Not -BeNullOrEmpty

			{ Set-TBORegSecurityDescriptor -ServerName localhost -Path $keyPath -SecurityDescriptor $saclBytes -Sections Sacl -Confirm:$false -ErrorAction Stop } | Should -Not -Throw
		}
		finally {
			if ($created) {
				Remove-TBORegKey -ServerName localhost -Path $keyPath -Confirm:$false -ErrorAction SilentlyContinue
			}
		}
	}
}
