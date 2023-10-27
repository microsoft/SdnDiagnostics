# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Using module .\SdnDiag.NetworkController.Helper.psm1
Import-Module $PSScriptRoot\SdnDiag.NetworkController.Helper.psm1
Import-Module $PSScriptRoot\..\SdnDiag.Common\SdnDiag.Common.psm1
Import-Module $PSScriptRoot\..\SdnDiag.Utilities\SdnDiag.Utilities.psm1

# create local variable to store configuration data
$configurationData = Import-PowerShellDataFile -Path $PSScriptRoot\SdnDiag.NetworkController.Config.psd1
New-Variable -Name 'SdnDiagnostics_NC' -Scope 'Script' -Force -Value @{
    Config = $configurationData
}

# due to limitations with defining dynamic value in psd1 file, need to populate the values here
$Script:SdnDiagnostics_NC.Config.Properties.CommonPaths.ServiceFabricLogDirectory = "$env:ProgramData\Microsoft\Service Fabric\log\Traces"
$Script:SdnDiagnostics_NC.Config.Properties.NetControllerStatePath = "$env:SystemRoot\Tracing\SdnDiagnostics\NetworkControllerState"

##### FUNCTIONS AUTO-POPULATED BELOW THIS LINE DURING BUILD #####
