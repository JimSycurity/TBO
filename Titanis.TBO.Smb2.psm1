# Load the compiled cmdlets from the module binary.
$binaryCandidates = @(
    (Join-Path -Path $PSScriptRoot -ChildPath 'Titanis.TBO.Smb2.PowerShell.dll'),
    (Join-Path -Path $PSScriptRoot -ChildPath 'Lib\Core\Titanis.TBO.Smb2.PowerShell.dll')
)

$binaryPath = $binaryCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $binaryPath) {
    throw "Module binary not found. Checked: $($binaryCandidates -join ', ')"
}

Import-Module -Name $binaryPath -PassThru | Out-Null
