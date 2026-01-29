# Build

## Prereqs

- .NET SDK (same major as repo toolchain).
- Pester for tests: `Install-Module -Name Pester -Scope CurrentUser`
- PSPublishModule for packaging: `Install-Module -Name PSPublishModule -Scope CurrentUser`

## Using local Titanis source

When building the TBO repo against a local Titanis checkout, set one of the following:

```powershell
Set-Item Env:\TITANIS_REPO C:\Data\Repos\Titanis
# or pass a property: /p:TitanisRepoRoot=C:\Data\Repos\Titanis
```

## Dev build (fast loop)

```powershell
dotnet build .\src\Titanis.TBO.Smb2.PowerShell.csproj -c Release /p:UseArtifactsOutput=false --nologo
```

Build output can be copied for ad-hoc testing:

```powershell
# robocopy .\src\bin\Release\net8.0\ C:\Temp\Titanis.TBO.Smb2 /E
```

## Dev build to C:\Temp

```powershell
dotnet build C:\Data\Repos\TBO\src\Titanis.TBO.Smb2.PowerShell.csproj -c Release /p:UseArtifactsOutput=false -o C:\Temp\Titanis.TBO.Smb2 --nologo
```

## Release build (packaging)

```powershell
# Bump the version (major|minor|patch) before commit.
.\Build\Update-Version.ps1 -Bump patch

# Release packaging with PSPublishModule (outputs to .\Artifacts\).
.\Build\Build-Module.ps1 -Configuration Release

# Skip tests if you need a quick packaging run (not recommended).
# .\Build\Build-Module.ps1 -Configuration Release -SkipTests
```

`Build-Module.ps1` runs Pester and uses `/p:UseArtifactsOutput=false` for the build step.

## Build Titanis directly (optional)

If you have Titanis changes and want to build them directly:

```powershell
dotnet build C:\Data\Repos\Titanis\src\net\Titanis.Smb2\Titanis.Smb2.csproj -c Release --nologo
```
