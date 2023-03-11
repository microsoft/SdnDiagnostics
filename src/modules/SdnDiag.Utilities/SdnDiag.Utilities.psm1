# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Using module .\SdnDiag.Utilities.Helper.psm1

# create local variable to store configuration data
$configurationData = Import-PowerShellDataFile -Path "$PSScriptRoot\SdnDiag.Utilities.Config.psd1"
New-Variable -Name 'SdnDiagnostics_Utilities' -Scope 'Local' -Force -Value @{
    Config = $configurationData
}

##### AUTO-GENERATED BELOW THIS LINE #####
