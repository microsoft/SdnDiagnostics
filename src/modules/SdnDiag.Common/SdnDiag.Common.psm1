# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Import-Module $PSScriptRoot\..\SdnDiag.Utilities\SdnDiag.Utilities.psm1

# create local variable to store configuration data
$configurationData = Import-PowerShellDataFile -Path "$PSScriptRoot\SdnDiag.Common.Config.psd1"
New-Variable -Name 'SdnDiagnostics_Common' -Scope 'Script' -Force -Value @{
    Cache = @{}
    Config = $configurationData
}

##### FUNCTIONS AUTO-POPULATED BELOW THIS LINE DURING BUILD #####
