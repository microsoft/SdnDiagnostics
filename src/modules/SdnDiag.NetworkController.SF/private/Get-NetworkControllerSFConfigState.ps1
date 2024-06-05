function Get-NetworkControllerSFConfigState {
    <#
    .SYNOPSIS
        Outputs a set of configuration state files for the network controller role.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .EXAMPLE
        PS> Get-NetworkControllerSFConfigState -OutputDirectory "C:\Temp\CSS_SDN"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    $currentErrorActionPreference = $ErrorActionPreference
    $ProgressPreference = 'SilentlyContinue'
    $ErrorActionPreference = 'SilentlyContinue'

    try {
        $config = Get-SdnModuleConfiguration -Role 'NetworkController_SF'
        [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath "ConfigState"

        if (-NOT (Initialize-DataCollection -Role $config.Name -FilePath $OutputDirectory.FullName -MinimumMB 100)) {
            "Unable to initialize environment for data collection for {0}" -f $config.Name | Trace-Output -Level:Error
            return
        }

        "Collect configuration state details for role {0}" -f $config.Name | Trace-Output
        # insert data collection datapoints
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }

    $ProgressPreference = 'Continue'
    $ErrorActionPreference = $currentErrorActionPreference
}
