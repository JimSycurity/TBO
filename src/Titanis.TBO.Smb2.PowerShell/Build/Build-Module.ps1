[CmdletBinding()]
param(
	[ValidateSet('Release', 'Debug')]
	[string]$Configuration = 'Release',
	[switch]$NoDotnetBuild,
	[string]$ModuleVersion
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$moduleRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $moduleRoot '..\..')).Path
$projectPath = Join-Path $moduleRoot 'Titanis.TBO.Smb2.PowerShell.csproj'
$manifestPath = Join-Path $moduleRoot 'Titanis.TBO.Smb2.psd1'
$metadataPath = Join-Path $PSScriptRoot 'METADATA.md'

if (-not (Test-Path -LiteralPath $projectPath)) {
	throw "Project file not found: $projectPath"
}

if (-not (Test-Path -LiteralPath $manifestPath)) {
	throw "Module manifest not found: $manifestPath"
}

if (-not (Test-Path -LiteralPath $metadataPath)) {
	throw "Metadata file not found: $metadataPath"
}

if (-not $NoDotnetBuild) {
	Write-Host "Building Titanis.TBO.Smb2.PowerShell ($Configuration)..." -ForegroundColor DarkGray
	$buildOutput = & dotnet build $projectPath -c $Configuration --nologo --verbosity quiet 2>&1
	if ($LASTEXITCODE -ne 0) {
		$buildOutput | Out-Host
		throw "dotnet build failed (exit $LASTEXITCODE)"
	}
}

if (-not (Get-Module -ListAvailable -Name PSPublishModule)) {
	throw "PSPublishModule not installed. Install with: Install-Module -Name PSPublishModule -Scope CurrentUser"
}

Import-Module PSPublishModule -ErrorAction Stop

$psd1 = Import-PowerShellDataFile -Path $manifestPath
$metadata = @{}
foreach ($line in Get-Content -Path $metadataPath) {
	if ($line -match '^\s*-\s*(?<key>[^:]+):\s*(?<value>.*)$') {
		$metadata[$matches['key'].Trim()] = $matches['value'].Trim()
	}
}

function Get-MetadataValue {
	param([string]$Key)
	if ($metadata.ContainsKey($Key)) { return $metadata[$Key] }
	return $null
}

$moduleVersionValue = $ModuleVersion
if (-not $moduleVersionValue) { $moduleVersionValue = Get-MetadataValue 'ModuleVersion' }
if (-not $moduleVersionValue) { $moduleVersionValue = $psd1.ModuleVersion }

$manifest = [ordered]@{
	ModuleVersion = $moduleVersionValue
	RootModule = $psd1.RootModule
	CmdletsToExport = $psd1.CmdletsToExport
	FunctionsToExport = $psd1.FunctionsToExport
	FormatsToProcess = @($psd1.FormatsToProcess)
}

$manifestCommand = Get-Command New-ConfigurationManifest -ErrorAction Stop
if (-not $manifestCommand.Parameters.ContainsKey('RootModule')) {
	[void]$manifest.Remove('RootModule')
}

$guidValue = Get-MetadataValue 'GUID'
if (-not $guidValue -and $psd1.GUID) { $guidValue = $psd1.GUID }
if ($guidValue) { $manifest.GUID = $guidValue }

$author = Get-MetadataValue 'Author'
if ($author) { $manifest.Author = $author } elseif ($psd1.Author) { $manifest.Author = $psd1.Author }

$companyName = Get-MetadataValue 'CompanyName'
if ($companyName) { $manifest.CompanyName = $companyName }

$copyright = Get-MetadataValue 'Copyright'
if ($copyright) { $manifest.Copyright = $copyright }

$description = Get-MetadataValue 'Description'
if ($description) { $manifest.Description = $description } elseif ($psd1.Description) { $manifest.Description = $psd1.Description }

$tagsRaw = Get-MetadataValue 'Tags (comma-separated)'
if ($tagsRaw) { $manifest.Tags = @($tagsRaw -split '\s*,\s*') }

$licenseUri = Get-MetadataValue 'LicenseUri'
if ($licenseUri) { $manifest.LicenseUri = $licenseUri }

$projectUri = Get-MetadataValue 'ProjectUri'
if ($projectUri) { $manifest.ProjectUri = $projectUri }

$releaseNotes = Get-MetadataValue 'ReleaseNotes'
if ($releaseNotes) { $manifest.ReleaseNotes = $releaseNotes }

$prerelease = Get-MetadataValue 'Prerelease'
if ($prerelease) { $manifest.Prerelease = $prerelease }

$compatiblePSEditions = Get-MetadataValue 'CompatiblePSEditions'
if ($compatiblePSEditions) { $manifest.CompatiblePSEditions = @($compatiblePSEditions -split '\s*,\s*') }

$powerShellVersion = Get-MetadataValue 'PowerShellVersion'
if ($powerShellVersion) { $manifest.PowerShellVersion = $powerShellVersion }

$requireLicenseAcceptance = Get-MetadataValue 'RequireLicenseAcceptance (true/false)'
if ($requireLicenseAcceptance) {
	switch ($requireLicenseAcceptance.ToLowerInvariant()) {
		'true' { $manifest.RequireLicenseAcceptance = $true }
		'false' { $manifest.RequireLicenseAcceptance = $false }
	}
}

$buildParams = @{
	ModuleName = 'Titanis.TBO.Smb2'
	ExitCode   = $true
}

Push-Location $moduleRoot
try {
	Build-Module @buildParams -Settings {
		New-ConfigurationManifest @manifest

		$newConfigurationBuildSplat = @{
			Enable                        = $true
			MergeModuleOnBuild            = $false
			ResolveBinaryConflicts        = $true
			ResolveBinaryConflictsName    = 'Titanis.TBO.Smb2.PowerShell'
			NETProjectPath                = $moduleRoot
			NETProjectName                = 'Titanis.TBO.Smb2.PowerShell'
			NETConfiguration              = $Configuration
			NETFramework                  = 'net8.0'
			NETHandleAssemblyWithSameName = $true
		}

		New-ConfigurationBuild @newConfigurationBuildSplat

		New-ConfigurationArtefact -Type Unpacked -Enable -Path "$PSScriptRoot\..\Artefacts\Unpacked\<TagModuleVersionWithPreRelease>"
		New-ConfigurationArtefact -Type Packed -Enable -Path "$PSScriptRoot\..\Artefacts\Packed" -IncludeTagName -ArtefactName "Titanis.TBO.Smb2.<TagModuleVersionWithPreRelease>.zip"
	}
} finally {
	Pop-Location
}
