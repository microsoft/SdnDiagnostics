# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

$configurationData = Import-PowerShellDataFile -Path "$PSScriptRoot\SdnDiagnostics.Config.psd1"
New-Variable -Name SdnDiagnostics -Scope Global -Force -Value @{
    Cache = @{}
    Config = @{}
    Credential = $null
    EnvironmentInfo = @{
        RestApiVersion = 'V1'
    }
    NcRestCredential = $null
    Settings = $configurationData
    TraceFilePath = $null
}
