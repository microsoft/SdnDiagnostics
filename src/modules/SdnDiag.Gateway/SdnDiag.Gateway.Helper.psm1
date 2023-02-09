# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

$configurationData = Import-PowerShellDataFile -Path "$PSScriptRoot\SdnDiag.Gateway.Config.psd1"
$Global:SdnDiagnostics.Config.Gateway = $configurationData
