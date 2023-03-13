# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
Using module .\SdnDiag.Health.Helper.psm1

Import-Module $PSScriptRoot\SdnDiag.Health.Helper.psm1
Import-Module $PSScriptRoot\..\SdnDiag.Utilities\SdnDiag.Utilities.psm1

# create local variable to store configuration data
<#
$configurationData = Import-PowerShellDataFile -Path "$PSScriptRoot\SdnDiag.Health.Config.psd1"
New-Variable -Name 'SdnDiagnostics_Health' -Scope 'Script' -Force -Value @{
    Config = $configurationData
}
#>

##### AUTO-GENERATED BELOW THIS LINE #####
