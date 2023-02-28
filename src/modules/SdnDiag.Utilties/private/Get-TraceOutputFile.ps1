# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-TraceOutputFile {
    return [System.IO.FileInfo]$global:SdnDiagnostics.TraceFilePath
}