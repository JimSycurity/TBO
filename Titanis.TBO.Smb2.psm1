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

function Out-File {
    [CmdletBinding(DefaultParameterSetName = 'FilePath')]
    param(
        [Parameter(ValueFromPipeline = $true)]
        $InputObject,

        [Parameter(Position = 0, ParameterSetName = 'FilePath')]
        [string]$FilePath,

        [Parameter(ParameterSetName = 'LiteralPath')]
        [string]$LiteralPath,

        [switch]$Append,
        [switch]$NoClobber,
        [switch]$Force,
        [switch]$NoNewline,
        [System.Text.Encoding]$Encoding,
        [int]$Width,
        [switch]$PassThru
    )

    begin {
        $path = if ($PSCmdlet.ParameterSetName -eq 'LiteralPath') { $LiteralPath } else { $FilePath }
        $provider = $null
        $drive = $null
        $isTboPath = $false

        if ($path) {
            try {
                $null = $PSCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($path, [ref]$provider, [ref]$drive)
                if ($provider -and $provider.Name -eq 'TBO.Smb2') {
                    $isTboPath = $true
                }
            }
            catch {
            }
        }

        if (-not $isTboPath) {
            $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('Microsoft.PowerShell.Utility\\Out-File', [System.Management.Automation.CommandTypes]::Cmdlet)
            $scriptCmd = { & $wrappedCmd @PSBoundParameters }
            $script:steppablePipeline = $scriptCmd.GetSteppablePipeline($MyInvocation.CommandOrigin)
            $script:steppablePipeline.Begin($PSCmdlet)
        }
        else {
            $script:buffer = New-Object System.Collections.Generic.List[object]
        }
    }

    process {
        if ($script:steppablePipeline) {
            $script:steppablePipeline.Process($_)
        }
        else {
            [void]$script:buffer.Add($InputObject)
        }
    }

    end {
        if ($script:steppablePipeline) {
            $script:steppablePipeline.End()
            return
        }

        $outStringParams = @{}
        if ($Width) { $outStringParams.Width = $Width }

        $content = $script:buffer | Microsoft.PowerShell.Utility\Out-String @outStringParams
        if ($NoNewline) {
            $content = $content -replace "(\r?\n)$", ""
        }

        $setParams = @{}
        if ($Encoding) { $setParams.Encoding = $Encoding }
        if ($Force) { $setParams.Force = $true }

        if ($PSCmdlet.ParameterSetName -eq 'LiteralPath') {
            $setParams.LiteralPath = $LiteralPath
        }
        else {
            $setParams.Path = $FilePath
        }

        if ($Append) {
            $setParams.Value = $content
            Microsoft.PowerShell.Management\Add-Content @setParams
        }
        else {
            if ($NoClobber) { $setParams.NoClobber = $true }
            $setParams.Value = $content
            Microsoft.PowerShell.Management\Set-Content @setParams
        }

        if ($PassThru) {
            $script:buffer
        }
    }
}

Export-ModuleMember -Function Out-File
