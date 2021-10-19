# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnSlbMuxConfigurationState {
    <#
    .SYNOPSIS
        Outputs a set of configuration state files for the load balancer role.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .EXAMPLE
        PS> Get-SdnSlbMuxConfigurationState -OutputDirectory "C:\Temp\CSS_SDN"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    $ProgressPreference = 'SilentlyContinue'

    try {
        $config = Get-SdnRoleConfiguration -Role:SoftwareLoadBalancer
        [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath "ConfigState"
        [System.IO.FileInfo]$regDir = Join-Path -Path $OutputDirectory.FullName -ChildPath "Registry"

        "Collect configuration state details for role {0}" -f $config.Name | Trace-Output

        if (!(Initialize-DataCollection -Role:SoftwareLoadBalancer -FilePath $OutputDirectory.FullName -MinimumMB 100)) {
            throw New-Object System.Exception("Unable to initialize environment for data collection")
        }

        # dump out the regkey properties
        Export-RegistryKeyConfigDetails -Path $config.properties.regKeyPaths -OutputDirectory $regDir.FullName

        # output slb configuration and states
        "Getting MUX Driver Control configuration settings" | Trace-Output -Level:Verbose
        MuxDriverControlConsole.exe /GetMuxState | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'GetMuxState' -FileType txt
        MuxDriverControlConsole.exe /GetMuxConfig | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'GetMuxConfig' -FileType txt
        MuxDriverControlConsole.exe /GetMuxStats | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'GetMuxStats' -FileType txt
        MuxDriverControlConsole.exe /GetMuxVipList | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'GetMuxVipList' -FileType txt
        MuxDriverControlConsole.exe /GetMuxDripList | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'GetMuxDripList' -FileType txt
        MuxDriverControlConsole.exe /GetStatelessVip | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'GetStatelessVip' -FileType txt
        MuxDriverControlConsole.exe /GetStatefulVip | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'GetStatefulVip' -FileType txt

        Get-GeneralConfigurationState -OutputDirectory $OutputDirectory.FullName
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }

    $ProgressPreference = 'Continue'
}
