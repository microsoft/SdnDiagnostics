# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

@{
    DefaultLogDirectory = "C:\Windows\Tracing\SDNDiagnostics\Logs"
    NetworkShareFolders = @(
        "CrashDumps",
        "NCApplicationCrashDumps",
        "NCApplicationLogs",
        "PerfCounters",
        "SdnDiagnostics",
        "Traces"
    )
    LogFileTypes = @(
        "*.log",
        "*.etl",
        "*.cab",
        "*.dmp"
        "*.trace"
        "*.zip"
        "*.blg"
        )
    Properties = @{
        EventLogProviders = @(
            "Application"
            "System"
        )
        EtwTraceProviders = @{}
    }
}
