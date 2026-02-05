[CmdletBinding()]
param(
	[ValidateSet('Release', 'Debug')]
	[string]$Configuration = 'Release',
	[switch]$NoDotnetBuild,
	[switch]$SkipTests,
	[string]$ModuleVersion
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$moduleRoot = $repoRoot
$projectPath = Join-Path $repoRoot 'src\Titanis.TBO.Smb2.PowerShell.csproj'
$manifestPath = Join-Path $repoRoot 'Titanis.TBO.Smb2.psd1'
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

if (-not $SkipTests) {
	if (-not (Get-Command Invoke-Pester -ErrorAction SilentlyContinue)) {
		throw "Pester is required to run tests. Install with: Install-Module -Name Pester -Scope CurrentUser"
	}
	Write-Host "Running Pester tests..." -ForegroundColor DarkGray
	$testPath = Join-Path $repoRoot 'test\powershell'
	$testCommand = @'
$ErrorActionPreference = 'Stop'
Import-Module Pester -ErrorAction Stop
$result = Invoke-Pester -Path '__TEST_PATH__' -PassThru
if ($result.FailedCount -gt 0) { exit 1 }
'@
	$testCommand = $testCommand.Replace('__TEST_PATH__', $testPath)
	& pwsh -NoProfile -Command $testCommand 2>&1 | ForEach-Object { $_ }
	$testExitCode = $LASTEXITCODE
	if ($testExitCode -ne 0) {
		throw "Pester tests failed."
	}
}

if (-not $NoDotnetBuild) {
	Write-Host "Building Titanis.TBO.Smb2.PowerShell ($Configuration)..." -ForegroundColor DarkGray
	# Avoid Titanis artifacts path issues when building from the TBO repo.
	$buildOutput = & dotnet build $projectPath -c $Configuration /p:UseArtifactsOutput=false --nologo --verbosity quiet 2>&1
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

Push-Location (Join-Path $repoRoot 'src')
$originalUseArtifactsOutput = $env:UseArtifactsOutput
$env:UseArtifactsOutput = 'false'
$dotnetWrapperRoot = $null
$dotnetWrapperPath = $null
$psPublishModule = Get-Module PSPublishModule
$originalModuleDotnetAliasDefinition = $null
try {
	$dotnetWrapperRoot = Join-Path $env:TEMP ("tbo-dotnet-wrapper-" + [Guid]::NewGuid().ToString("N"))
	$dotnetWrapperPath = Join-Path $dotnetWrapperRoot 'dotnet.cmd'
	$dotnetRealPath = (Get-Command dotnet -CommandType Application -ErrorAction Stop).Source
	$wrapperContent = @"
@echo off
setlocal
set "DOTNET_REAL=$dotnetRealPath"
if /I "%~1"=="publish" (
  "%DOTNET_REAL%" %* -p:UseArtifactsOutput=false
) else (
  "%DOTNET_REAL%" %*
)
exit /b %errorlevel%
"@
	$null = New-Item -Path $dotnetWrapperRoot -ItemType Directory -Force
	Set-Content -Path $dotnetWrapperPath -Value $wrapperContent -Encoding ASCII
	if ($psPublishModule) {
		$originalModuleDotnetAliasDefinition = & $psPublishModule {
			(Get-Alias dotnet -ErrorAction SilentlyContinue).Definition
		}
		& $psPublishModule {
			param($wrapperPath)
			Set-Alias -Name dotnet -Value $wrapperPath -Scope Script
		} $dotnetWrapperPath
	}

	Build-Module @buildParams -Settings {
		New-ConfigurationManifest @manifest

		$newConfigurationBuildSplat = @{
			Enable                        = $true
			MergeModuleOnBuild            = $false
			ResolveBinaryConflicts        = $true
			ResolveBinaryConflictsName    = 'Titanis.TBO.Smb2.PowerShell'
			NETProjectPath                = (Join-Path $repoRoot 'src')
			NETProjectName                = 'Titanis.TBO.Smb2.PowerShell'
			NETConfiguration              = $Configuration
			NETFramework                  = 'net8.0'
			NETHandleAssemblyWithSameName = $true
		}

		New-ConfigurationBuild @newConfigurationBuildSplat

		# Use US spelling for output paths.
		New-ConfigurationArtefact -Type Unpacked -Enable -Path "$PSScriptRoot\..\Artifacts\Unpacked\<TagModuleVersionWithPreRelease>"
		New-ConfigurationArtefact -Type Packed -Enable -Path "$PSScriptRoot\..\Artifacts\Packed" -IncludeTagName -ArtefactName "Titanis.TBO.Smb2.<TagModuleVersionWithPreRelease>.zip"
	}
} finally {
	if ($psPublishModule) {
		if ($originalModuleDotnetAliasDefinition) {
			& $psPublishModule {
				param($aliasDefinition)
				Set-Alias -Name dotnet -Value $aliasDefinition -Scope Script
			} $originalModuleDotnetAliasDefinition
		} else {
			& $psPublishModule {
				Remove-Item -Path alias:dotnet -ErrorAction SilentlyContinue
			}
		}
	}
	if ($dotnetWrapperRoot) {
		Remove-Item -Path $dotnetWrapperRoot -Recurse -Force -ErrorAction SilentlyContinue
	}
	if ($null -eq $originalUseArtifactsOutput) {
		Remove-Item env:UseArtifactsOutput -ErrorAction SilentlyContinue
	} else {
		$env:UseArtifactsOutput = $originalUseArtifactsOutput
	}
	Pop-Location
}
