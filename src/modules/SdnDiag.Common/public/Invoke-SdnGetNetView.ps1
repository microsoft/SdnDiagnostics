function Invoke-SdnGetNetView {
    <#
    .SYNOPSIS
        Invokes Get-Netview function on the specified ComputerNames.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .PARAMETER BackgroundThreads
        Maximum number of background tasks, from 0 - 16. Defaults to 5.
    .PARAMETER SkipAdminCheck
        If present, skip the check for admin privileges before execution. Note that without admin privileges, the scope and
        usefulness of the collected data is limited.
    .PARAMETER SkipLogs
        If present, skip the EVT and WER logs gather phases.
    .PARAMETER SkipNetsh
        If present, skip all Netsh commands.
    .PARAMETER SkipNetshTrace
        If present, skip the Netsh Trace data gather phase.
    .PARAMETER SkipCounters
        If present, skip the Windows Performance Counters collection phase.
    .PARAMETER SkipWindowsRegistry
        If present, skip exporting Windows Registry keys.
    .PARAMETER SkipVm
        If present, skip the Virtual Machine (VM) data gather phases.
    .EXAMPLE
        PS> Invoke-SdnGetNetView -OutputDirectory "C:\Temp\CSS_SDN"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 16)]
        [int]$BackgroundThreads = 5,

        [Parameter(Mandatory = $false)]
        [switch]$SkipAdminCheck,

        [Parameter(Mandatory = $false)]
        [switch]$SkipLogs,

        [Parameter(Mandatory = $false)]
        [switch]$SkipNetsh,

        [Parameter(Mandatory = $false)]
        [switch]$SkipNetshTrace,

        [Parameter(Mandatory = $false)]
        [switch]$SkipCounters,

        [Parameter(Mandatory = $false)]
        [switch]$SkipWindowsRegistry,

        [Parameter(Mandatory = $false)]
        [switch]$SkipVm
    )

    try {
        # check to see if Get-NetView module is loaded into the runspace, if so, remove it
        if (Get-Module -Name Get-NetView) {
            Remove-Module -Name Get-NetView -Force
        }
        # import the Get-NetView module from the external packages
        $module = Get-Item -Path "$PSScriptRoot\..\..\externalPackages\Get-NetView.*\Get-NetView.psd1" -ErrorAction Stop
        Import-Module -Name $module.FullName -Force

        # initialize the data collection environment which will ensure the path exists and has enough space
        [string]$outDir = Join-Path -Path $OutputDirectory -ChildPath "NetView"
        if (-NOT (Initialize-DataCollection -FilePath $outDir -MinimumMB 200)) {
            "Unable to initialize environment for data collection" | Trace-Output -Level:Error
            return
        }

        # execute Get-NetView with specified parameters and redirect all streams to null to prevent unnecessary noise on the screen
        Get-NetView @PSBoundParameters *>$null

        # remove the uncompressed files and folders to free up ~ 1.5GB of space
        $compressedArchive = Get-ChildItem -Path $outDir -Filter "*.zip"
        if ($compressedArchive) {
            Get-ChildItem -Path $outDir -Exclude *.zip | Remove-Item -Recurse -Confirm:$false
        }

        return $compressedArchive.FullName
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
