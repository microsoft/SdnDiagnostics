function Get-WorkingDirectory {
    return [System.IO.FileInfo]$global:SdnDiagnostics.Settings.WorkingDirectory
}
