# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Using module .\SdnDiag.Utilities.Helper.psm1

# create local variable to store configuration data
$configurationData = Import-PowerShellDataFile -Path "$PSScriptRoot\SdnDiag.Utilities.Config.psd1"

New-Variable -Name 'SdnDiagnostics_Utilities' -Scope 'Script' -Force -Value @{
    Cache = @{
        FilesExcludedFromCleanup = @()
        TraceFilePath = $null
        WorkingDirectory = $null
    }
    Config = $configurationData
}

##### FUNCTIONS AUTO-POPULATED BELOW THIS LINE DURING BUILD #####
