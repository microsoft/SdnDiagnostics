# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Import-Module $PSScriptRoot\..\SdnDiag.Utilities\SdnDiag.Utilities.psm1

# create local variable to store configuration data
$configurationData = Import-PowerShellDataFile -Path "$PSScriptRoot\SdnDiag.Gateway.Config.psd1"
New-Variable -Name 'SdnDiagnostics_Gateway' -Scope 'Local' -Force -Value @{
    Config = $configurationData
}

##### AUTO-GENERATED BELOW THIS LINE #####
