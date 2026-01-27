param(
	[ValidateSet('major', 'minor', 'patch')]
	[string]$Bump = 'patch'
)

$metadataPath = Join-Path $PSScriptRoot 'METADATA.md'
$manifestPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Titanis.TBO.Smb2.psd1'

if (-not (Test-Path $metadataPath)) {
	throw "Metadata file not found: $metadataPath"
}

if (-not (Test-Path $manifestPath)) {
	throw "Module manifest not found: $manifestPath"
}

$metadata = Get-Content -Path $metadataPath -Raw
$metadataMatch = [regex]::Match($metadata, 'ModuleVersion:\s*([0-9]+)\.([0-9]+)(?:\.([0-9]+))?')
if (-not $metadataMatch.Success) {
	throw "ModuleVersion not found in $metadataPath"
}

$major = [int]$metadataMatch.Groups[1].Value
$minor = [int]$metadataMatch.Groups[2].Value
$patch = if ($metadataMatch.Groups[3].Success) { [int]$metadataMatch.Groups[3].Value } else { 0 }

switch ($Bump) {
	'major' { $major++; $minor = 0; $patch = 0 }
	'minor' { $minor++; $patch = 0 }
	'patch' { $patch++ }
}

$newVersion = "$major.$minor.$patch"

$metadata = [regex]::Replace(
	$metadata,
	'(ModuleVersion:\s*)[0-9]+(?:\.[0-9]+){1,2}',
	'${1}' + $newVersion
)

$manifest = Get-Content -Path $manifestPath -Raw
$manifest = [regex]::Replace(
	$manifest,
	"(ModuleVersion\s*=\s*)'[^']+'",
	"`$1'$newVersion'"
)

Set-Content -Path $metadataPath -Value $metadata
Set-Content -Path $manifestPath -Value $manifest

Write-Host "Updated version to $newVersion in METADATA.md and Titanis.TBO.Smb2.psd1"
