# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Using module .\..\SdnDiag.Common\SdnDiag.Common.Helper.psm1
Using module .\SdnDiag.Utilities.Helper.psm1

New-Variable -Name 'SdnDiagnostics_Utilities' -Scope 'Script' -Force -Value @{
    Cache = @{
        FilesExcludedFromCleanup = @()
        TraceFilePath = $null
        WorkingDirectory = $null
    }
    Config = @{
        FolderPathsAllowedForCleanup = @(
            "$env:SystemRoot \Tracing\SdnDiag"
            "$env:SystemRoot \Tracing\SdnDiag\*"
        )
        DefaultModuleDirectory = "$env:ProgramFiles\WindowsPowerShell\Modules"
        WorkingDirectory = "$env:SystemRoot \Tracing\SdnDiag"
    }
}

##### FUNCTIONS AUTO-POPULATED BELOW THIS LINE DURING BUILD #####
