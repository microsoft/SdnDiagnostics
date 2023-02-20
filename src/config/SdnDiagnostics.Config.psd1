@{
    DefaultLogDirectory = "C:\Windows\tracing\SDNDiagnostics\Logs"
    FilesExcludedFromCleanup = @()
    FolderPathsAllowedForCleanup = @(
        "C:\Windows\Tracing\SdnDiag"
        "C:\Windows\Tracing\SdnDiag\*"
    )
    WorkingDirectory = "C:\Windows\Tracing\SdnDiag"
}
