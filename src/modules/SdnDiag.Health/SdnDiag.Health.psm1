# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Using module .\SdnDiag.Health.Helper.psm1

Import-Module $PSScriptRoot\SdnDiag.Health.Helper.psm1
Import-Module $PSScriptRoot\..\SdnDiag.Common\SdnDiag.Common.psm1
Import-Module $PSScriptRoot\..\SdnDiag.NetworkController.FC\SdnDiag.NetworkController.FC.psm1
Import-Module $PSScriptRoot\..\SdnDiag.NetworkController.SF\SdnDiag.NetworkController.SF.psm1
Import-Module $PSScriptRoot\..\SdnDiag.Utilities\SdnDiag.Utilities.psm1

# create local variable to store configuration data
$configurationData = Import-PowerShellDataFile -Path "$PSScriptRoot\SdnDiag.Health.Config.psd1"
New-Variable -Name 'SdnDiagnostics_Health' -Scope 'Script' -Force -Value @{
    Cache = @{}
    Config = $configurationData
}

##### FUNCTIONS AUTO-POPULATED BELOW THIS LINE DURING BUILD #####
