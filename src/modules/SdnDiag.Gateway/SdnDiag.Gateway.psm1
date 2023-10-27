# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Import-Module $PSScriptRoot\..\SdnDiag.Common\SdnDiag.Common.psm1
Import-Module $PSScriptRoot\..\SdnDiag.Utilities\SdnDiag.Utilities.psm1

# create local variable to store configuration data
$configurationData = Import-PowerShellDataFile -Path "$PSScriptRoot\SdnDiag.Gateway.Config.psd1"
New-Variable -Name 'SdnDiagnostics_Gateway' -Scope 'Script' -Force -Value @{
    Config = $configurationData
}

# due to limitations with defining dynamic value in psd1 file, need to populate the values here
$Script:SdnDiagnostics.Config.Properties.CommonPaths.RasGatewayTraces = "$env:SystemRoot\Tracing"

##### FUNCTIONS AUTO-POPULATED BELOW THIS LINE DURING BUILD #####
