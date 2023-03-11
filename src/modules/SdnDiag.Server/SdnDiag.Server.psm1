# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Using module .\SdnDiag.Server.Helper.psm1
Import-Module $PSScriptRoot\..\SdnDiag.Utilities\SdnDiag.Utilities.psm1

# create local variable to store configuration data
$configurationData = Import-PowerShellDataFile -Path "$PSScriptRoot\SdnDiag.Server.Config.psd1"
New-Variable -Name 'SdnDiagnostics_Server' -Scope 'Local' -Force -Value @{
    Config = $configurationData
}

##### AUTO-GENERATED BELOW THIS LINE #####
