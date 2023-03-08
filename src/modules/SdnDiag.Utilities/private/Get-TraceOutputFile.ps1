function Get-TraceOutputFile {
    return [System.IO.FileInfo]$global:SdnDiagnostics.TraceFilePath
}
