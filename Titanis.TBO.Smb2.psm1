# Load the compiled cmdlets from the module binary.
$binaryCandidates = @(
    # Prefer Lib\Core when present because it keeps managed dependencies (e.g. Microsoft.Data.Sqlite)
    # co-located with the module binary for reliable assembly probing.
    (Join-Path -Path $PSScriptRoot -ChildPath 'Lib\Core\Titanis.TBO.Smb2.PowerShell.dll'),
    (Join-Path -Path $PSScriptRoot -ChildPath 'Titanis.TBO.Smb2.PowerShell.dll')
)

function Test-TboBinaryCandidateHasSqliteDeps {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $false }

    $dir = Split-Path -Parent $Path
    if (-not $dir) { return $false }

    # Cache features depend on Microsoft.Data.Sqlite (and its SQLitePCLRaw dependencies) being present
    # next to the module binary.
    $deps = @(
        'Microsoft.Data.Sqlite.dll',
        'SQLitePCLRaw.batteries_v2.dll',
        'SQLitePCLRaw.core.dll',
        'SQLitePCLRaw.provider.e_sqlite3.dll'
    )

    foreach ($dep in $deps) {
        if (-not (Test-Path -LiteralPath (Join-Path $dir $dep))) {
            return $false
        }
    }

    return $true
}

# Prefer a candidate that includes SQLite dependencies (enables Get-TBOCacheInfo and -Cache/-CachePath).
$binaryPath = $binaryCandidates | Where-Object { Test-TboBinaryCandidateHasSqliteDeps -Path $_ } | Select-Object -First 1
if (-not $binaryPath) {
    $binaryPath = $binaryCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($binaryPath) {
        Write-Warning "TBO: Loaded module binary '$binaryPath' but SQLite dependencies were not found next to it; cache features may fail. Prefer importing from the repo root or rebuilding via Build\\Build-Module.ps1."
    }
}
if (-not $binaryPath) {
    throw "Module binary not found. Checked: $($binaryCandidates -join ', ')"
}

Import-Module -Name $binaryPath -PassThru -ErrorAction Stop | Out-Null
