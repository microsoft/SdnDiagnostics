# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

$sdnDiagConfig = Import-PowerShellDataFile -Path "$PSScriptRoot\SdnDiagnostics.Config.psd1"
$gwConfig = Import-PowerShellDataFile -Path "$PSScriptRoot\modules\SdnDiag.Gateway\SdnDiag.Gateway.Config.psd1"
$ncConfig = Import-PowerShellDataFile -Path "$PSScriptRoot\modules\SdnDiag.NetworkController\SdnDiag.NetworkController.Config.psd1"
$muxConfig = Import-PowerShellDataFile -Path "$PSScriptRoot\modules\SdnDiag.LoadBalancer\SdnDiag.LoadBalancer.Mux.Config.psd1"
$serverConfig = Import-PowerShellDataFile -Path "$PSScriptRoot\modules\SdnDiag.Server\SdnDiag.Server.Config.psd1"

New-Variable -Name SdnDiagnostics -Scope Global -Force -Value @{
    Cache = @{}
    Config = @{
        Gateway = $gwConfig
        LoadBalancerMux = $muxConfig
        NetworkController = $ncConfig
        Server = $serverConfig
    }
    Credential = $null
    EnvironmentInfo = @{
        RestApiVersion = 'V1'
    }
    NcRestCredential = $null
    Settings = $sdnDiagConfig
    TraceFilePath = $null
}
