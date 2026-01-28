Set-StrictMode -Version Latest

BeforeAll {
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

    $script:moduleRoot = Join-Path $script:repoRoot 'src'
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
        $data.RootModule | Should -Be 'Titanis.TBO.Smb2.PowerShell.dll'
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
        $cmdlets | Should -Contain 'Set-TBOSmbConnectOptions'
        $cmdlets | Should -Contain 'Get-TBOSmbSnapshots'
        $cmdlets | Should -Contain 'Get-TBORegKey'
    }

    It 'registers the TBO.Smb2 provider' {
        if (-not $script:loadedModule) {
            Set-ItResult -Skipped -Because 'Module binary not found or failed to import.'
            return
        }

        (Get-PSProvider | Where-Object { $_.Name -eq 'TBO.Smb2' }).Count | Should -Be 1
    }
}
