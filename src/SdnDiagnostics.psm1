# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Import-Module $PSScriptRoot\SdnDiagnostics.Helper.psm1

# create local variable to store configuration data
$configurationData = Import-PowerShellDataFile -Path "$PSScriptRoot\SdnDiagnostics.Config.psd1"
New-Variable -Name 'SdnDiagnostics' -Scope 'Global' -Force -Value @{
    Cache = @{}
    EnvironmentInfo = @{
        RestApiVersion = 'V1'
    }
    Config = $configurationData
}

# in some instances where powershell has been left open for a long time, we can leave behind sessions that are no longer valid
# so we will want to clean up any SDN related sessions on module import
Remove-PSRemotingSession

# define this to prevent truncated results
$FormatEnumerationLimit = -1
