function New-TraceOutputFile {

    try {
        # make sure that directory path exists, else create the folder structure required
        $workingDir = Get-WorkingDirectory
        if (-NOT (Test-Path -Path $workingDir -PathType Container)) {
            $null = New-Item -Path $workingDir -ItemType Directory -Force
        }

        # build the trace file path and set global variable
        [System.String]$fileName = "SdnDiagnostics_TraceOutput_{0}.csv" -f (Get-Date).ToString('yyyyMMdd')
        [System.IO.FileInfo]$filePath = Join-Path -Path $workingDir -ChildPath $fileName
        Set-TraceOutputFile -Path $filePath.FullName

        # configure the cache to not cleanup the trace file
        $SdnDiagnostics_Utilities.Cache.FilesExcludedFromCleanup += $filePath.Name
        "TraceFile: {0}" -f $filePath.FullName | Trace-Output -Level:Verbose
    }
    catch {
        $_.Exception | Write-Error
    }
}
