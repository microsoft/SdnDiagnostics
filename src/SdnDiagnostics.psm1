# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Import-Module $PSScriptRoot\SdnDiagnostics.Helper.psm1

New-Variable -Name 'SdnDiagnostics' -Scope 'Global' -Force -Value @{
    Cache = @{}
    EnvironmentInfo = @{
        RestApiVersion = 'V1'
    }
    Config = @{
        # when creating remote sessions, the module will be imported automatically
        ImportModuleOnRemoteSession = $false

        # determines from a global perspective if we should be disabling automatic seeding of module to remote nodes
        DisableModuleSeeding = $false

        # by default will just leverage the name of the module, however if using custom path not under default module directory
        # can update this to be the full path name to module, which will be used on PSRemoteSessions
        ModuleName = 'SdnDiagnostics'

        # defines if this module is running on Windows Server, Azure Stack HCI or Azure Stack Hub
        # supported values are 'WindowsServer', 'AzureStackHCI', 'AzureStackHub'
        Mode = "WindowsServer"
    }
}

# in some instances where powershell has been left open for a long time, we can leave behind sessions that are no longer valid
# so we will want to clean up any SDN related sessions on module import
Remove-PSRemotingSession

function Get-SdnConfigState {
    <#
    .SYNOPSIS
        Gets the configuration state of the computer.
    .PARAMETER Role
        The SDN role of the computer.
    .PARAMETER OutputDirectory
        The directory to output the configuration state to.
    .EXAMPLE
        PS> Get-SdnConfigState -Role Server -OutputDirectory C:\Temp
    #>

    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)]
        [ValidateSet('Common', 'Gateway', 'NetworkController', 'Server', 'LoadBalancerMux')]
        [String]$Role,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    switch ($Role) {
        'Common' {
            Get-CommonConfigState -OutputDirectory $OutputDirectory
        }
        'Gateway' {
            Get-GatewayConfigState -OutputDirectory $OutputDirectory
        }
        'NetworkController' {
            Get-NetworkControllerConfigState -OutputDirectory $OutputDirectory
        }
        'Server' {
            Get-ServerConfigState -OutputDirectory $OutputDirectory
        }
        'LoadBalancerMux' {
            Get-SlbMuxConfigState -OutputDirectory $OutputDirectory
        }
    }
}
