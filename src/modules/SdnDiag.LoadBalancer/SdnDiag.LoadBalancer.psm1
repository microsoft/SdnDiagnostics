# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Import-Module $PSScriptRoot\..\SdnDiag.Common\SdnDiag.Common.psm1
Import-Module $PSScriptRoot\..\SdnDiag.Utilities\SdnDiag.Utilities.psm1

# create local variable to store configuration data
$configurationData = Import-PowerShellDataFile -Path "$PSScriptRoot\SdnDiag.LoadBalancer.Config.psd1"
New-Variable -Name 'SdnDiagnostics_SLB' -Scope 'Script' -Force -Value @{
    Config = $configurationData
}

##### FUNCTIONS AUTO-POPULATED BELOW THIS LINE DURING BUILD #####
