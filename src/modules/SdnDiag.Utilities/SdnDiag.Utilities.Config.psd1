# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

@{
    FolderPathsAllowedForCleanup = @(
        "C:\Windows\Tracing\SdnDiag"
        "C:\Windows\Tracing\SdnDiag\*"
    )
    DefaultModuleDirectory = "$($env:ProgramFiles)\WindowsPowerShell\Modules"
    WorkingDirectory = "$($env:SystemRoot)\Tracing\SdnDiag"
}
