# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

using module ".\classes\SdnDiag.Classes.psm1"

$sdnDiagConfig = Import-PowerShellDataFile -Path "$PSScriptRoot\config\SdnDiagnostics.Config.psd1"
$gwConfig = Import-PowerShellDataFile -Path "$PSScriptRoot\config\SdnDiag.Gateway.Config.psd1"
$ncConfig = Import-PowerShellDataFile -Path "$PSScriptRoot\config\SdnDiag.NetworkController.Config.psd1"
$muxConfig = Import-PowerShellDataFile -Path "$PSScriptRoot\config\SdnDiag.LoadBalancer.Mux.Config.psd1"
$serverConfig = Import-PowerShellDataFile -Path "$PSScriptRoot\config\SdnDiag.Server.Config.psd1"

New-Variable -Name SdnDiagnostics -Scope Global -Force -Value @{
    Cache = @{}
    Config = @{
        Gateway = $gwConfig
        LoadBalancerMux = $muxConfig
        NetworkController = $ncConfig
        Server = $serverConfig
    }
    Credential = $null
    InfrastructureInfo = @{
        RestApiVersion = 'V1'
    }
    NcRestCredential = $null
    Settings = $sdnDiagConfig
    TraceFilePath = $null
}
