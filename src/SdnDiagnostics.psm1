# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Import-Module $PSScriptRoot\SdnDiagnostics.Helper.psm1

# create local variable to store configuration data
$configurationData = Import-PowerShellDataFile -Path "$PSScriptRoot\SdnDiagnostics.Config.psd1"
New-Variable -Name 'SdnDiagnostics' -Scope 'Global' -Force -Value @{
    Cache = @{}
    EnvironmentInfo = @{
        RestApiVersion = 'V1'
    }
    Config = $configurationData
}
