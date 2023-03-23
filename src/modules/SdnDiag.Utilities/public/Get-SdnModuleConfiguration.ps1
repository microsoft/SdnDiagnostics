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
        [SdnModules]$Role
    )

    $path = "SdnDiag.{0}\SdnDiag.{0}.Config.psd1" -f $Role
    $moduleConfig = Get-Item -Path $PSScriptRoot\..\$path -ErrorAction SilentlyContinue
    if ($moduleConfig) {
        "Reading configuration data from {0}" -f $moduleConfig.FullName | Trace-Output -Level:Verbose
        $configurationData = Import-PowerShellDataFile -Path $moduleConfig.FullName
    }

    return $configurationData
}
