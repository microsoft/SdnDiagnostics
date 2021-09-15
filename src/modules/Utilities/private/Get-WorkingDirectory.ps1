# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-WorkingDirectory {
    return [System.IO.FileInfo]$global:SdnDiagnostics.Settings.workingDirectory
}
