# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function New-WorkingDirectory {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.IO.FileInfo]$Path = $global:SdnDiagnostics.Settings.workingDirectory
    )

    try {

        # create the working directory and set the global cache
        if(!(Test-Path -Path $Path.FullName -PathType Container)){
            $null = New-Item -Path $Path.FullName -ItemType Directory -Force
        }

        # create the trace file
        New-TraceOutputFile
    }
    catch {
        $_.Exception | Write-Error
    }
}
