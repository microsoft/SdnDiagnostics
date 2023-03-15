function Get-SdnModuleConfiguration {
    <#
    .SYNOPSIS
        Returns the configuration data related to the sub modules within SdnDiagnostics.
    .PARAMETER Role
        The SDN role that you want to return configuration data for.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnDiag.Common.Helper.SdnRoles]$Role
    )

    switch ($Role) {
        'Gateway' {
            $configurationData = Import-PowerShellDataFile -Path "$PSScriptRoot\..\SdnDiag.Gateway\SdnDiag.Gateway.Config.psd1"
        }

        'LoadBalancerMux' {
            $configurationData = Import-PowerShellDataFile -Path "$PSScriptRoot\..\SdnDiag.LoadBalancer\SdnDiag.LoadBalancer.Config.psd1"
        }

        'NetworkController' {
            $configurationData = Import-PowerShellDataFile -Path "$PSScriptRoot\..\SdnDiag.NetworkController\SdnDiag.NetworkController.Config.psd1"
        }

        'Server' {
            $configurationData = Import-PowerShellDataFile -Path "$PSScriptRoot\..\SdnDiag.Server\SdnDiag.Server.Config.psd1"
        }
    }

    return $configurationData
}
