@{
    DefaultLogDirectory = "C:\Windows\tracing\SDNDiagnostics\Logs"
    FilesExcludedFromCleanup = @()
    FolderPathsAllowedForCleanup = @(
        "C:\Windows\Tracing\SdnDataCollection"
        "C:\Windows\Tracing\SdnDataCollection\*"
    )
    WorkingDirectory = "C:\Windows\Tracing\SdnDataCollection"
}
