# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Import-Module $PSScriptRoot\SdnDiagnostics.Helper.psm1

New-Variable -Name 'SdnDiagnostics' -Scope 'Global' -Force -Value @{
    Cache = @{}
    EnvironmentInfo = @{
        RestApiVersion = 'V1'
    }
    Config = @{
        # when creating remote sessions, the module will be imported automatically
        ImportModuleOnRemoteSession = $false

        # reference https://learn.microsoft.com/en-us/powershell/module/powershellget/install-module?view=powershellget-2.
        ModuleRootDirectory = "$env:ProgramFiles\WindowsPowerShell\Modules"

        # defines if this module is running on Windows Server, Azure Stack HCI or Azure Stack Hub
        # supported values are 'WindowsServer', 'AzureStackHCI', 'AzureStackHub'
        Mode = "WindowsServer"
    }
}

# in some instances where powershell has been left open for a long time, we can leave behind sessions that are no longer valid
# so we will want to clean up any SDN related sessions on module import
Remove-PSRemotingSession
