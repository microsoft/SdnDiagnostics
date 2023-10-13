# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

@{
    # when creating remote sessions, the module will be imported automatically
    ImportModuleOnRemoteSession = $false

    # reference https://learn.microsoft.com/en-us/powershell/module/powershellget/install-module?view=powershellget-2.x
    ModuleRootDirectory = "C:\Program Files\WindowsPowerShell\Modules"

    # defines if this module is running on Windows Server, Azure Stack HCI or Azure Stack Hub
    # supported values are 'WindowsServer', 'AzureStackHCI', 'AzureStackHub'
    Mode = "WindowsServer"
}
