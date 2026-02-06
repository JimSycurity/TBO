Set-StrictMode -Version Latest

BeforeAll {
    $script:testHarnessPath = Join-Path $PSScriptRoot 'TboTestHarness.ps1'
    if (Test-Path -LiteralPath $script:testHarnessPath) {
        . $script:testHarnessPath
    }
    function Get-RepoRoot {
        param([string[]]$paths)

        foreach ($path in $paths) {
            if (-not $path) { continue }
            $current = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
            while ($current -and -not (Test-Path (Join-Path $current.FullName '.git'))) {
                $current = $current.Parent
            }
            if ($current) {
                return $current.FullName
            }
        }

        return $null
    }

    function Get-HelpModuleBinary {
        param([string]$repoRoot)

        $candidateRoots = @(
            (Join-Path $repoRoot 'src\bin\Release\net8.0\publish'),
            (Join-Path $repoRoot 'src\bin\Debug\net8.0\publish')
        )

        foreach ($root in $candidateRoots) {
            $binary = Join-Path $root 'Titanis.TBO.Smb2.PowerShell.dll'
            $helpXml = Join-Path $root 'Titanis.TBO.Smb2.PowerShell.dll-Help.xml'
            if ((Test-Path -LiteralPath $binary) -and (Test-Path -LiteralPath $helpXml)) {
                return $binary
            }
        }

        return $null
    }

    $scriptPath = $PSCommandPath
    if (-not $scriptPath) { $scriptPath = $PSScriptRoot }
    if (-not $scriptPath) {
        $command = $MyInvocation.MyCommand
        if ($command -and $command.PSObject.Properties.Match('Path').Count -gt 0) {
            $scriptPath = $command.Path
        }
    }

    $testRoot = if ($scriptPath) { Split-Path -Parent $scriptPath } else { (Get-Location).Path }
    $script:repoRoot = Get-RepoRoot -paths @($testRoot, (Get-Location).Path)

    if (-not $script:repoRoot) {
        throw "Could not locate repo root (.git)."
    }

    $script:moduleRoot = $script:repoRoot
    $script:manifestPath = Join-Path $script:moduleRoot 'Titanis.TBO.Smb2.psd1'
    $script:formatPath = Join-Path $script:moduleRoot 'Format.ps1xml'
    $script:helpRoot = Join-Path $script:moduleRoot 'en-US'
}

Describe 'Titanis.TBO.Smb2 manifest and help' {
    It 'loads the module manifest data' {
        Test-Path $script:manifestPath | Should -BeTrue
        $data = Import-PowerShellDataFile -Path $script:manifestPath
        $data | Should -Not -BeNullOrEmpty
    }

    It 'defines required manifest fields' {
        $data = Import-PowerShellDataFile -Path $script:manifestPath
        $data.ModuleVersion | Should -Not -BeNullOrEmpty
        $data.RootModule | Should -Be 'Titanis.TBO.Smb2.psm1'
        $data.GUID | Should -Not -BeNullOrEmpty
        $data.FormatsToProcess | Should -Contain 'Format.ps1xml'
    }

    It 'includes the format definition file' {
        Test-Path $script:formatPath | Should -BeTrue
    }

    It 'includes about help files' {
        Test-Path $script:helpRoot | Should -BeTrue
        (Get-ChildItem -Path $script:helpRoot -Filter 'about_TBO_*.help.txt').Count | Should -BeGreaterThan 0
    }

    It 'about help files include standard sections' {
        $files = Get-ChildItem -Path $script:helpRoot -Filter 'about_TBO_*.help.txt'
        foreach ($file in $files) {
            $content = Get-Content -Path $file.FullName -Raw
            $hasCommentHelp = ($content -match '\.SYNOPSIS') -and ($content -match '\.DESCRIPTION')
            $hasAboutHelp = ($content -match '(?m)^TOPIC') -and ($content -match '(?m)^LONG DESCRIPTION')
            ($hasCommentHelp -or $hasAboutHelp) | Should -BeTrue
        }
    }
}

Describe 'Titanis.TBO.Smb2 binary module (if built)' {
    BeforeAll {
        $script:loadedModule = $null
        $binaryRoot = Join-Path $script:repoRoot 'artifacts\lib\bin\Titanis.TBO.Smb2.PowerShell'
        $binary = Get-ChildItem -Path $binaryRoot -Recurse -Filter 'Titanis.TBO.Smb2.PowerShell.dll' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
        if ($binary) {
            try {
                $script:loadedModule = Import-Module $binary.FullName -Force -PassThru -ErrorAction Stop
            } catch {
                $script:loadedModule = $null
            }
        }
    }

    It 'imports the binary module when present' {
        if (-not $script:loadedModule) {
            Set-ItResult -Skipped -Because 'Module binary not found or failed to import.'
            return
        }

        $script:loadedModule.Name | Should -Not -BeNullOrEmpty
    }

    It 'exports expected cmdlets' {
        if (-not $script:loadedModule) {
            Set-ItResult -Skipped -Because 'Module binary not found or failed to import.'
            return
        }

        $cmdlets = Get-Command -Module $script:loadedModule.Name | Select-Object -ExpandProperty Name
        $cmdlets | Should -Contain 'Set-TBOConnectOptions'
        $cmdlets | Should -Contain 'Set-TBOSmbConnectOptions'
        $cmdlets | Should -Contain 'Get-TBOSmbSnapshots'
        $cmdlets | Should -Contain 'Get-TBORegKey'
        $cmdlets | Should -Contain 'Get-TBORegSecurityDescriptor'
        $cmdlets | Should -Contain 'Set-TBORegSecurityDescriptor'
        $cmdlets | Should -Contain 'Find-TBODpapiBlobs'
        $cmdlets | Should -Contain 'Get-TBODpapiMasterKeyLocations'
        $cmdlets | Should -Contain 'Get-TBODpapiMasterKeys'
        $cmdlets | Should -Contain 'Get-TBODpapiMasterKeyHashes'
    }

    It 'registers the TBO.Smb2 provider' {
        if (-not $script:loadedModule) {
            Set-ItResult -Skipped -Because 'Module binary not found or failed to import.'
            return
        }

        (Get-PSProvider | Where-Object { $_.Name -eq 'TBO.Smb2' }).Count | Should -Be 1
    }

    It 'validates Set-TBORegSecurityDescriptor inputs when using -WhatIf' {
        if (-not $script:loadedModule) {
            Set-ItResult -Skipped -Because 'Module binary not found or failed to import.'
            return
        }

        $sddl = 'O:BAG:BAD:(A;;KR;;;SY)'
        $raw = New-Object System.Security.AccessControl.RawSecurityDescriptor $sddl
        $bytes = New-Object byte[] $raw.BinaryLength
        $raw.GetBinaryForm($bytes, 0)

        { Set-TBORegSecurityDescriptor -ServerName testhost -Path HKLM\SOFTWARE -SecurityDescriptor $bytes -WhatIf } | Should -Not -Throw
        if ($IsWindows) {
            { Set-TBORegSecurityDescriptor -ServerName testhost -Path HKLM\SOFTWARE -SecurityDescriptor $sddl -WhatIf } | Should -Not -Throw
        }

        { Set-TBORegSecurityDescriptor -ServerName testhost -Path HKLM\SOFTWARE -SecurityDescriptor $bytes -Sections None -WhatIf } | Should -Throw
        { Set-TBORegSecurityDescriptor -ServerName testhost -Path HKLM\SOFTWARE -SecurityDescriptor 123 -WhatIf } | Should -Throw
    }
}

Describe 'Titanis.TBO.Smb2 cmdlet help' {
    BeforeAll {
        $script:helpModule = $null
        $binary = Get-HelpModuleBinary -repoRoot $script:repoRoot
        if ($binary) {
            try {
                $script:helpModule = Import-Module -Name $binary -Force -PassThru -ErrorAction Stop
            } catch {
                $script:helpModule = $null
            }
        }
    }

    It 'provides synopsis, description, and examples for each cmdlet' {
        if (-not $script:helpModule) {
            Set-ItResult -Skipped -Because 'Publish output with help XML not found; build the module to validate Get-Help content.'
            return
        }

        $cmdlets = Get-Command -Module $script:helpModule.Name -CommandType Cmdlet
        $cmdlets | Should -Not -BeNullOrEmpty

        foreach ($cmdlet in $cmdlets) {
            $help = Get-Help -Name $cmdlet.Name -Full -ErrorAction Stop
            $help | Should -Not -BeNullOrEmpty
            $help.Synopsis | Should -Not -BeNullOrEmpty

            $description = ''
            if ($help.PSObject.Properties.Match('Description').Count -gt 0) {
                $description = $help.Description | ForEach-Object { $_.Text } | Out-String
            }
            if (-not $description.Trim() -and $help.PSObject.Properties.Match('Details').Count -gt 0) {
                $description = $help.Details.Description | ForEach-Object { $_.Text } | Out-String
            }
            $description.Trim() | Should -Not -BeNullOrEmpty

            $examples = @($help.Examples.Example)
            $examples.Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'TBO test harness' {
    It 'allows overriding provider info for SmbCmdlet' {
        if (-not (Get-Command -Name Import-TboModuleForTests -ErrorAction SilentlyContinue)) {
            Set-ItResult -Skipped -Because 'Test harness helpers not available.'
            return
        }

        try {
            Import-TboModuleForTests -RepoRoot $script:repoRoot | Out-Null
        } catch {
            Set-ItResult -Skipped -Because 'Module binary not found; build the module to enable mock provider tests.'
            return
        }
        if (-not ('Titanis.Tbo.Smb2.PowerShell.MockSmbProviderInfo' -as [type])) {
            Set-ItResult -Skipped -Because 'Mock provider type not found; build the module to enable mock provider tests.'
            return
        }

        $script:capturedServer = $null
        $mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot `
            -GetConnectParametersFor { param($serverName, $defaultIfNone) $mock.DefaultConnectParameters } `
            -SetConnectParameters { param($serverName, $parameters) $script:capturedServer = $serverName }

        $scope = Use-TboProviderInfoOverride -ProviderInfo $mock
        try {
            Set-TBOConnectOptions -ServerName 'fileserver'
        } finally {
            $scope.Dispose()
        }

        $script:capturedServer | Should -Be 'fileserver'
    }
}

Describe 'DPAPI cmdlets with fake SMB file system' {
    It 'scans for DPAPI blobs using a fake SMB file system' {
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
        $magic = 0x01,0x00,0x00,0x00,0xD0,0x8C,0x9D,0xDF,0x01,0x15,0xD1,0x11,0x8C,0x7A,0x00,0xC0,0x4F,0xC2,0x97,0xEB,0xFF
        $fake.AddDirectory("\\server\C$\Temp") | Out-Null
        $fake.AddFile("\\server\C$\Temp\blob.bin", [byte[]]$magic) | Out-Null

        $mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot
        $mock.FileSystem = $fake

        $scope = Use-TboProviderInfoOverride -ProviderInfo $mock
        try {
            $results = @(Find-TBODpapiBlobs -ServerName server -Path "\\server\C$\Temp" -Recurse)
        } finally {
            $scope.Dispose()
        }

        $results | Should -Not -BeNullOrEmpty
        $match = $results | Where-Object { $_.Path -like "*\Temp\blob.bin" } | Select-Object -First 1
        $match | Should -Not -BeNullOrEmpty
        $match.MatchOffset | Should -Be 0
        $match.Source | Should -Be 'File'
    }

    It 'enumerates master key locations using a fake SMB file system' {
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
        $guid = [Guid]::Parse('1c39564b-6f6e-4ac0-9715-cda5503e6290')
        $guidBytes = $guid.ToByteArray()
        $versionBytes = [System.BitConverter]::GetBytes(2)
        $lengthBytes = [System.BitConverter]::GetBytes(16)
        $preferredBytes = $versionBytes + $lengthBytes + $guidBytes
        $root = "\\server\C$\Windows\System32\Microsoft\Protect\S-1-5-18"
        $fake.AddDirectory($root) | Out-Null
        $fake.AddFile("$root\Preferred", $preferredBytes) | Out-Null
        $fake.AddFile("$root\$guid", [byte[]](0x01,0x02,0x03)) | Out-Null

        $mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot
        $mock.FileSystem = $fake

        $scope = Use-TboProviderInfoOverride -ProviderInfo $mock
        try {
            $results = @(Get-TBODpapiMasterKeyLocations -ServerName server -Scope Machine -ShareName C$)
        } finally {
            $scope.Dispose()
        }

        $results | Should -Not -BeNullOrEmpty
        $match = $results | Where-Object { $_.MasterKeyGuid -eq $guid.ToString() } | Select-Object -First 1
        $match | Should -Not -BeNullOrEmpty
        $match.IsPreferred | Should -BeTrue
        $match.Scope | Should -Be 'Machine'
    }

    It 'dumps DPAPImk hashes for user master keys using a fake SMB file system' {
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

        function New-FakeMasterKeyFileBytes {
            param(
                [Parameter(Mandatory=$true)][Guid]$Guid,
                [Parameter(Mandatory=$true)][byte[]]$Salt16,
                [Parameter(Mandatory=$true)][uint32]$Rounds,
                [Parameter(Mandatory=$true)][uint32]$HashAlgo,
                [Parameter(Mandatory=$true)][uint32]$CipherAlgo,
                [Parameter(Mandatory=$true)][byte[]]$CipherText
            )

            $mkBlock =
                [System.BitConverter]::GetBytes([uint32]2) +
                $Salt16 +
                [System.BitConverter]::GetBytes($Rounds) +
                [System.BitConverter]::GetBytes($HashAlgo) +
                [System.BitConverter]::GetBytes($CipherAlgo) +
                $CipherText

            $guidTextBytes = [System.Text.Encoding]::Unicode.GetBytes($Guid.ToString())

            $zero32 = [System.BitConverter]::GetBytes([uint32]0)
            $zero64 = [System.BitConverter]::GetBytes([uint64]0)
            $policy = [System.BitConverter]::GetBytes([uint32]0)
            $mkLen = [System.BitConverter]::GetBytes([uint64]$mkBlock.Length)

            return (
                [System.BitConverter]::GetBytes([uint32]2) +
                $zero32 + $zero32 +
                $guidTextBytes +
                $zero32 + $zero32 +
                $policy +
                $mkLen + $zero64 + $zero64 + $zero64 +
                $mkBlock
            )
        }

        $domainSid = 'S-1-5-21-1111111111-2222222222-3333333333-1101'
        $localSid  = 'S-1-5-21-1111111111-2222222222-3333333333-1102'

        $domainGuid = [Guid]::Parse('0a9f3f91-51c6-43b8-9edb-3fbe5c8f6a1f')
        $localGuid  = [Guid]::Parse('c7d15f8f-7fb9-4bc7-8cbe-2c1b7b1a6b9c')

        $salt = [byte[]](1..16)
        $cipherText = [byte[]](17..32)

        $domainFileBytes = New-FakeMasterKeyFileBytes -Guid $domainGuid -Salt16 $salt -Rounds 1000 -HashAlgo 32782 -CipherAlgo 26128 -CipherText $cipherText
        $localFileBytes  = New-FakeMasterKeyFileBytes -Guid $localGuid  -Salt16 $salt -Rounds 1000 -HashAlgo 32782 -CipherAlgo 26128 -CipherText $cipherText

        $domainDir = "\\server\C$\Users\domuser\AppData\Roaming\Microsoft\Protect\$domainSid"
        $localDir  = "\\server\C$\Users\localuser\AppData\Roaming\Microsoft\Protect\$localSid"

        $versionBytes = [System.BitConverter]::GetBytes(2)
        $lengthBytes = [System.BitConverter]::GetBytes(16)
        $domainPreferredBytes = $versionBytes + $lengthBytes + $domainGuid.ToByteArray()
        $localPreferredBytes  = $versionBytes + $lengthBytes + $localGuid.ToByteArray()

        $fake.AddDirectory($domainDir) | Out-Null
        $fake.AddFile("$domainDir\Preferred", $domainPreferredBytes) | Out-Null
        $fake.AddFile("$domainDir\BK-TESTDOM", [byte[]](0x01,0x02,0x03)) | Out-Null
        $fake.AddFile("$domainDir\$domainGuid", $domainFileBytes) | Out-Null

        $fake.AddDirectory($localDir) | Out-Null
        $fake.AddFile("$localDir\Preferred", $localPreferredBytes) | Out-Null
        $fake.AddFile("$localDir\$localGuid", $localFileBytes) | Out-Null

        $mock = New-TboMockProviderInfo -RepoRoot $script:repoRoot
        $mock.FileSystem = $fake

        $scope = Use-TboProviderInfoOverride -ProviderInfo $mock
        try {
            $results = @(Get-TBODpapiMasterKeyHashes -ServerName server -Scope User -ShareName C$)
        } finally {
            $scope.Dispose()
        }

        $results | Should -Not -BeNullOrEmpty

        $domain = $results | Where-Object { $_.MasterKeyGuid -eq $domainGuid.ToString() } | Select-Object -First 1
        $domain | Should -Not -BeNullOrEmpty
        $domain.IsPreferred | Should -BeTrue
        $domain.IsDomain | Should -BeTrue
        $domain.HashContext | Should -Be 3

        $saltHex = ($salt | ForEach-Object { $_.ToString('x2') }) -join ''
        $cipherHex = ($cipherText | ForEach-Object { $_.ToString('x2') }) -join ''
        $expectedDomainHash = '$DPAPImk$2*3*' + $domainSid + '*aes256*sha512*1000*' + $saltHex + '*32*' + $cipherHex
        $domain.Hash | Should -Be $expectedDomainHash
        $domain.HashLine | Should -Be "{$($domainGuid.ToString())}:$expectedDomainHash"

        $local = $results | Where-Object { $_.MasterKeyGuid -eq $localGuid.ToString() } | Select-Object -First 1
        $local | Should -Not -BeNullOrEmpty
        $local.IsPreferred | Should -BeTrue
        $local.IsDomain | Should -BeFalse
        $local.HashContext | Should -Be 1
        $expectedLocalHash = '$DPAPImk$2*1*' + $localSid + '*aes256*sha512*1000*' + $saltHex + '*32*' + $cipherHex
        $local.Hash | Should -Be $expectedLocalHash
        $local.HashLine | Should -Be "{$($localGuid.ToString())}:$expectedLocalHash"
    }
}
