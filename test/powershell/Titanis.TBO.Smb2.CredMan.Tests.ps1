Set-StrictMode -Version Latest

BeforeAll {
    $script:testHarnessPath = Join-Path $PSScriptRoot 'TboTestHarness.ps1'
    if (Test-Path -LiteralPath $script:testHarnessPath) {
        . $script:testHarnessPath
    }

    if (Get-Command -Name Get-TboRepoRoot -ErrorAction SilentlyContinue) {
        $script:repoRoot = Get-TboRepoRoot -Paths @($PSScriptRoot, (Get-Location).Path)
    }
}

Describe 'CredMan cmdlets with fake SMB file system' {
    It 'enumerates user and machine credential files' {
        if (-not (Get-Command -Name Import-TboModuleForTests -ErrorAction SilentlyContinue)) {
            Set-ItResult -Skipped -Because 'Test harness helpers not available.'
            return
        }

        try {
            Import-TboModuleForTests -RepoRoot $script:repoRoot | Out-Null
        } catch {
            Set-ItResult -Skipped -Because 'Module binary not found; build the module to enable fake SMB tests.'
            return
        }

        if (-not ('Titanis.Tbo.Smb2.PowerShell.FakeSmbFileSystem' -as [type])) {
            Set-ItResult -Skipped -Because 'Fake SMB file system not found; rebuild the module to include it.'
            return
        }

        $fake = [Titanis.Tbo.Smb2.PowerShell.FakeSmbFileSystem]::new()
        $vaultGuid = [Guid]::Parse('c6b2799d-b539-4b70-9b96-c9673c7f7bcd').ToString()
        $fake.AddDirectory('\\server\C$\Users\jsmith\AppData\Local\Microsoft\Credentials') | Out-Null
        $fake.AddFile('\\server\C$\Users\jsmith\AppData\Local\Microsoft\Credentials\cred1', [byte[]](0x01)) | Out-Null
        $fake.AddDirectory("\\server\C$\Users\jsmith\AppData\Local\Microsoft\Vault\$vaultGuid") | Out-Null
        $fake.AddFile("\\server\C$\Users\jsmith\AppData\Local\Microsoft\Vault\$vaultGuid\vault.dat", [byte[]](0x02)) | Out-Null
        $fake.AddDirectory('\\server\C$\Users\Public\AppData\Local\Microsoft\Credentials') | Out-Null
        $fake.AddFile('\\server\C$\Users\Public\AppData\Local\Microsoft\Credentials\pubcred', [byte[]](0x03)) | Out-Null
        $fake.AddDirectory('\\server\C$\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials') | Out-Null
        $fake.AddFile('\\server\C$\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\syscred', [byte[]](0x04)) | Out-Null

        $mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot
        $mock.FileSystem = $fake

        $scope = Use-TboProviderInfoOverride -ProviderInfo $mock
        try {
            $userResults = @(Get-TBOCredManFiles -ServerName server -Scope User -UserName 'js*')
            $machineResults = @(Get-TBOCredManFiles -ServerName server -Scope Machine)
        } finally {
            $scope.Dispose()
        }

        $userResults | Should -Not -BeNullOrEmpty
        @($userResults | Where-Object Container -eq 'Credentials').Count | Should -Be 1
        @($userResults | Where-Object Container -eq 'Vault').Count | Should -Be 1
        @($userResults | Where-Object VaultGuid -eq $vaultGuid).Count | Should -Be 1

        $machineResults | Should -Not -BeNullOrEmpty
        $machineResults[0].Scope | Should -Be 'Machine'
        @($machineResults | Where-Object IsSystemProfile).Count | Should -BeGreaterThan 0
    }

    It 'scans credential files for DPAPI blob offsets' {
        if (-not (Get-Command -Name Import-TboModuleForTests -ErrorAction SilentlyContinue)) {
            Set-ItResult -Skipped -Because 'Test harness helpers not available.'
            return
        }

        try {
            Import-TboModuleForTests -RepoRoot $script:repoRoot | Out-Null
        } catch {
            Set-ItResult -Skipped -Because 'Module binary not found; build the module to enable fake SMB tests.'
            return
        }

        if (-not ('Titanis.Tbo.Smb2.PowerShell.FakeSmbFileSystem' -as [type])) {
            Set-ItResult -Skipped -Because 'Fake SMB file system not found; rebuild the module to include it.'
            return
        }

        $fake = [Titanis.Tbo.Smb2.PowerShell.FakeSmbFileSystem]::new()
        $magic = 0x01,0x00,0x00,0x00,0xD0,0x8C,0x9D,0xDF,0x01,0x15,0xD1,0x11,0x8C,0x7A,0x00,0xC0,0x4F,0xC2,0x97,0xEB
        $payload = [byte[]]((0xAA,0xBB,0xCC,0xDD) + $magic + 0xEE)
        $fake.AddDirectory('\\server\C$\Users\jsmith\AppData\Local\Microsoft\Credentials') | Out-Null
        $fake.AddFile('\\server\C$\Users\jsmith\AppData\Local\Microsoft\Credentials\cred1', $payload) | Out-Null

        $mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot
        $mock.FileSystem = $fake

        $scope = Use-TboProviderInfoOverride -ProviderInfo $mock
        try {
            $entry = Get-TBOCredManEntry -ServerName server -Path '\\server\C$\Users\jsmith\AppData\Local\Microsoft\Credentials\cred1' -IncludeRawBytes
        } finally {
            $scope.Dispose()
        }

        $entry | Should -Not -BeNullOrEmpty
        $entry.HasDpapiBlob | Should -BeTrue
        $entry.DpapiBlobOffset | Should -Be 4
        $entry.RawBytes.Length | Should -Be $entry.BytesScanned
    }

    It 'reports parse failures when DPAPI blob data is truncated' {
        if (-not (Get-Command -Name Import-TboModuleForTests -ErrorAction SilentlyContinue)) {
            Set-ItResult -Skipped -Because 'Test harness helpers not available.'
            return
        }

        try {
            Import-TboModuleForTests -RepoRoot $script:repoRoot | Out-Null
        } catch {
            Set-ItResult -Skipped -Because 'Module binary not found; build the module to enable fake SMB tests.'
            return
        }

        if (-not ('Titanis.Tbo.Smb2.PowerShell.FakeSmbFileSystem' -as [type])) {
            Set-ItResult -Skipped -Because 'Fake SMB file system not found; rebuild the module to include it.'
            return
        }

        $fake = [Titanis.Tbo.Smb2.PowerShell.FakeSmbFileSystem]::new()
        $magic = 0x01,0x00,0x00,0x00,0xD0,0x8C,0x9D,0xDF,0x01,0x15,0xD1,0x11,0x8C,0x7A,0x00,0xC0,0x4F,0xC2,0x97,0xEB
        $fake.AddDirectory('\\server\C$\Users\jsmith\AppData\Local\Microsoft\Credentials') | Out-Null
        $fake.AddFile('\\server\C$\Users\jsmith\AppData\Local\Microsoft\Credentials\cred2', [byte[]]$magic) | Out-Null

        $mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot
        $mock.FileSystem = $fake

        $scope = Use-TboProviderInfoOverride -ProviderInfo $mock
        try {
            $entry = Get-TBOCredManEntry -ServerName server -Path '\\server\C$\Users\jsmith\AppData\Local\Microsoft\Credentials\cred2' -MasterKeyBytes ([byte[]](0x01,0x02,0x03))
        } finally {
            $scope.Dispose()
        }

        $entry | Should -Not -BeNullOrEmpty
        $entry.FailureReason | Should -Match 'Failed to parse DPAPI blob'
    }
}
