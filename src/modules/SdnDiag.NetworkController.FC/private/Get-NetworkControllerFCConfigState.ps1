function Get-NetworkControllerFCConfigState {
    <#
    .SYNOPSIS
        Outputs a set of configuration state files for the network controller role.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .EXAMPLE
        PS> Get-NetworkControllerFCConfigState -OutputDirectory "C:\Temp\CSS_SDN"
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
        $config = Get-SdnModuleConfiguration -Role 'NetworkController_FC'
        [string]$outDir = Join-Path -Path $OutputDirectory.FullName -ChildPath "ConfigState"
        [string]$regDir = Join-Path -Path $OutputDirectory.FullName -ChildPath "Registry"

        if (-NOT (Initialize-DataCollection -Role $config.Name -FilePath $outDir -MinimumMB 10)) {
            "Unable to initialize environment for data collection for {0}" -f $config.Name | Trace-Output -Level:Error
            return
        }

        "Collect configuration state details for role {0}" -f $config.Name | Trace-Output

        # collect registry configuration information
        Export-RegistryKeyConfigDetails -Path $config.properties.regKeyPaths -OutputDirectory $regDir
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }

    $ProgressPreference = 'Continue'
    $ErrorActionPreference = $currentErrorActionPreference
}
