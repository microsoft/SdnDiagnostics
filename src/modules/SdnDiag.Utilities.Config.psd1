# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

@{
    FolderPathsAllowedForCleanup = @(
        "C:\Windows\Tracing\SdnDiag"
        "C:\Windows\Tracing\SdnDiag\*"
    )
    DefaultModuleDirectory = "C:\Program Files\WindowsPowerShell\Modules\SdnDiagnostics"
    WorkingDirectory = "C:\Windows\Tracing\SdnDiag"
    ExportFileJsonDepth = @{
        3 = @(
            'Get-NetAdapterChecksumOffload'
            'Get-NetAdapterLso'
            'Get-NetAdapterRdma'
            'Get-NetAdapterRsc'
            'Get-NetIPConfiguration'
            'Get-SdnVfpVmSwitchPort'
        )
    }
}
