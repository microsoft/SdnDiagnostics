# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function New-TraceOutputFile {

    try {
        # make sure that directory path exists, else create the folder structure required
        [System.IO.FileInfo]$workingDir = Get-WorkingDirectory
        if(!(Test-Path -Path $workingDir.FullName -PathType Container)){
            $workingDir = New-Item -Path $workingDir.FullName -ItemType Directory -Force
        }

        # build the trace file path and set global variable
        [System.String]$fileName = "SdnDiagnostics_TraceOutput_{0}.csv" -f (Get-Date).ToString('yyyyMMdd')
        [System.IO.FileInfo]$filePath = Join-Path -Path $workingDir.FullName -ChildPath $fileName
        Set-TraceOutputFile -Path $filePath.FullName

        "TraceFile: {0}" -f $filePath.FullName | Trace-Output -Level:Verbose
    }
    catch {
        $_.Exception | Write-Error
    }
}