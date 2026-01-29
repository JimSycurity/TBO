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

        $script:isTboPath = $isTboPath
        $script:buffer = New-Object System.Collections.Generic.List[object]
    }

    process {
        [void]$script:buffer.Add($InputObject)
    }

    end {
        if (-not $script:isTboPath) {
            $outParams = @{}
            if ($PSCmdlet.ParameterSetName -eq 'LiteralPath') {
                $outParams.LiteralPath = $LiteralPath
            }
            else {
                $outParams.FilePath = $FilePath
            }

            if ($Append) { $outParams.Append = $true }
            if ($NoClobber) { $outParams.NoClobber = $true }
            if ($Force) { $outParams.Force = $true }
            if ($NoNewline) { $outParams.NoNewline = $true }
            if ($Encoding) { $outParams.Encoding = $Encoding }
            if ($Width) { $outParams.Width = $Width }
            if ($PassThru) { $outParams.PassThru = $true }

            $outParams.InputObject = $script:buffer
            Microsoft.PowerShell.Utility\Out-File @outParams
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

# Ensure the shim wins over the built-in cmdlet in the caller's session.
try {
    if (-not (Get-Command Out-File -CommandType Function -ErrorAction SilentlyContinue)) {
        Set-Item -Path Function:\global:Out-File -Value $function:Out-File -Force
    }
}
catch {
}
