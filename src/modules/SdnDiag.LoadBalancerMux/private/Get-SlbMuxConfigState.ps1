function Get-SlbMuxConfigState {
    <#
    .SYNOPSIS
        Outputs a set of configuration state files for the load balancer role.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .EXAMPLE
        PS> Get-SlbMuxConfigState -OutputDirectory "C:\Temp\CSS_SDN"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    $currentErrorActionPreference = $ErrorActionPreference
    $ProgressPreference = 'SilentlyContinue'
    $ErrorActionPreference = 'Ignore'

    try {
        $config = Get-SdnModuleConfiguration -Role 'LoadBalancerMux'
        [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath "ConfigState"
        [System.IO.FileInfo]$regDir = Join-Path -Path $OutputDirectory.FullName -ChildPath "Registry"

        "Collect configuration state details for role {0}" -f $config.Name | Trace-Output

        if (-NOT (Initialize-DataCollection -Role $config.Name -FilePath $OutputDirectory.FullName -MinimumMB 100)) {
            "Unable to initialize environment for data collection" | Trace-Output -Level:Error
            return
        }

        Export-RegistryKeyConfigDetails -Path $config.properties.regKeyPaths -OutputDirectory $regDir.FullName
        Get-CommonConfigState -OutputDirectory $OutputDirectory.FullName

        # output slb configuration and states
        "Getting MUX Driver Control configuration settings" | Trace-Output -Level:Verbose
        Get-SdnMuxState | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType json
        Get-SdnMuxDistributedRouterIP | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType json
        Get-SdnMuxStatefulVip | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType json
        Get-SdnMuxStatelessVip | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType json
        Get-SdnMuxStats | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType json
        Get-SdnMuxVip | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType json
        Get-SdnMuxVipConfig | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType json
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }

    $ProgressPreference = 'Continue'
    $ErrorActionPreference = $currentErrorActionPreference
}
