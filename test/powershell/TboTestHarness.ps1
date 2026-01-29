Set-StrictMode -Version Latest

function Get-TboRepoRoot {
	param([string[]]$Paths)

	foreach ($path in $Paths) {
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

function Get-TboPublishRoot {
	param([string]$RepoRoot)

	$candidates = @(
		(Join-Path $RepoRoot 'src\bin\Release\net8.0\publish'),
		(Join-Path $RepoRoot 'src\bin\Debug\net8.0\publish')
	)

	foreach ($root in $candidates) {
		$binary = Join-Path $root 'Titanis.TBO.Smb2.PowerShell.dll'
		if (Test-Path -LiteralPath $binary) {
			return $root
		}
	}

	return $null
}

function Import-TboModuleForTests {
	param([string]$RepoRoot)

	if (-not $RepoRoot) {
		$RepoRoot = Get-TboRepoRoot -Paths @($PSScriptRoot, (Get-Location).Path)
	}
	if (-not $RepoRoot) {
		throw 'Unable to locate repo root to import module.'
	}

	$manifest = Join-Path $RepoRoot 'Titanis.TBO.Smb2.psd1'
	if (-not (Test-Path -LiteralPath $manifest)) {
		throw "Module manifest not found at $manifest."
	}

	Import-Module -Name $manifest -Force -ErrorAction Stop | Out-Null
	return $RepoRoot
}

function New-TboMockProviderInfo {
	param(
		[string]$RepoRoot,
		[scriptblock]$GetConnectParametersFor,
		[scriptblock]$SetConnectParameters,
		[scriptblock]$OpenServerServiceSessionAsync,
		[scriptblock]$OpenRemoteRegistrySessionAsync,
		[scriptblock]$DisconnectServerAsync,
		[scriptblock]$DisconnectAllAsync,
		[scriptblock]$LogException
	)

	Import-TboModuleForTests -RepoRoot $RepoRoot | Out-Null
	$mock = [Titanis.Tbo.Smb2.PowerShell.MockSmbProviderInfo]::new()

	if ($GetConnectParametersFor) { $mock.GetConnectParametersForFunc = [Func[string, bool, object]]$GetConnectParametersFor }
	if ($SetConnectParameters) { $mock.SetConnectParametersAction = [Action[string, object]]$SetConnectParameters }
	if ($OpenServerServiceSessionAsync) { $mock.OpenServerServiceSessionAsyncFunc = [Func[string, System.Threading.CancellationToken, System.Threading.Tasks.Task[Titanis.Tbo.Smb2.PowerShell.ServerServiceSession]]]$OpenServerServiceSessionAsync }
	if ($OpenRemoteRegistrySessionAsync) { $mock.OpenRemoteRegistrySessionAsyncFunc = [Func[string, System.Threading.CancellationToken, System.Threading.Tasks.Task[Titanis.Tbo.Smb2.PowerShell.RemoteRegistrySession]]]$OpenRemoteRegistrySessionAsync }
	if ($DisconnectServerAsync) { $mock.DisconnectServerAsyncFunc = [Func[string, Nullable[int], bool, System.Threading.Tasks.Task]]$DisconnectServerAsync }
	if ($DisconnectAllAsync) { $mock.DisconnectAllAsyncFunc = [Func[bool, System.Threading.Tasks.Task]]$DisconnectAllAsync }
	if ($LogException) { $mock.LogExceptionAction = [Action[string, System.Exception]]$LogException }

	return $mock
}

function Use-TboProviderInfoOverride {
	param(
		[Parameter(Mandatory = $true)]
		[object]$ProviderInfo
	)

	$cmdletType = [Titanis.Tbo.Smb2.PowerShell.SmbCmdlet]
	$flags = [System.Reflection.BindingFlags]::Static -bor [System.Reflection.BindingFlags]::NonPublic
	$property = $cmdletType.GetProperty('ProviderInfoOverride', $flags)
	if (-not $property) {
		throw 'Unable to locate ProviderInfoOverride on SmbCmdlet.'
	}

	$previous = $property.GetValue($null, $null)
	$property.SetValue($null, $ProviderInfo, $null)

	$capturedProperty = $property
	$capturedPrevious = $previous
	$disposer = New-Object psobject
	$disposer | Add-Member -MemberType ScriptMethod -Name Dispose -Value ({
		param()
		$capturedProperty.SetValue($null, $capturedPrevious, $null)
	}.GetNewClosure())
	return $disposer
}
