# Load the compiled cmdlets from the module binary.
$binaryPath = Join-Path -Path $PSScriptRoot -ChildPath 'Titanis.TBO.Smb2.PowerShell.dll'
if (-not (Test-Path -LiteralPath $binaryPath)) {
    throw "Module binary not found: $binaryPath"
}

Import-Module -Name $binaryPath -PassThru | Out-Null
