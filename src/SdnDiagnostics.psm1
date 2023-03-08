. "$PSScriptRoot\enums\SdnDiag.Enums.ps1"
. "$PSScriptRoot\classes\SdnDiag.Classes.ps1"
. "$PSScriptRoot\modules\SdnDiag.Common.ps1"
. "$PSScriptRoot\modules\SdnDiag.Gateway.ps1"
. "$PSScriptRoot\modules\SdnDiag.Health.ps1"
. "$PSScriptRoot\modules\SdnDiag.LoadBalancer.ps1"
. "$PSScriptRoot\modules\SdnDiag.NetworkController.ps1"
. "$PSScriptRoot\modules\SdnDiag.Server.ps1"
. "$PSScriptRoot\modules\SdnDiag.Utilities.ps1"
. "$PSScriptRoot\SdnDiagnostics.ArgCompleter.ps1"

$sdnDiagConfig = Import-PowerShellDataFile -Path "$PSScriptRoot\config\SdnDiag.psd1"
$gwConfig = Import-PowerShellDataFile -Path "$PSScriptRoot\config\SdnDiag.Gateway.psd1"
$ncConfig = Import-PowerShellDataFile -Path "$PSScriptRoot\config\SdnDiag.NetworkController.psd1"
$muxConfig = Import-PowerShellDataFile -Path "$PSScriptRoot\config\SdnDiag.LoadBalancer.Mux.psd1"
$serverConfig = Import-PowerShellDataFile -Path "$PSScriptRoot\config\SdnDiag.Server.psd1"

New-Variable -Name SdnDiagnostics -Scope Global -Force -Value @{
    Cache = @{}
    Config = @{
        Gateway = $gwConfig
        LoadBalancerMux = $muxConfig
        NetworkController = $ncConfig
        Server = $serverConfig
    }
    EnvironmentInfo = @{
        RestApiVersion = 'V1'
    }
    Settings = $sdnDiagConfig
    TraceFilePath = $null
}

$ErrorActionPreference = 'Continue'
