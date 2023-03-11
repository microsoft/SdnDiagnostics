# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

@{
    FilesExcludedFromCleanup = @()
    FolderPathsAllowedForCleanup = @(
        "C:\Windows\Tracing\SdnDiag"
        "C:\Windows\Tracing\SdnDiag\*"
    )
    WorkingDirectory = "C:\Windows\Tracing\SdnDiag"
}
