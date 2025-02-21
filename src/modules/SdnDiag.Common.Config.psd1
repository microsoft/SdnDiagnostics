# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

@{
    DefaultLogDirectory = "C:\Windows\Tracing\SDNDiagnostics"
    DefaultLogFolders = @(
        "CrashDumps",
        "NCApplicationCrashDumps",
        "NCApplicationLogs",
        "PerfCounters",
        "SdnDiagnostics",
        "Traces"
    )
    LogFileTypes = @(
        "*.blg",
        "*.cab",
        "*.dmp"
        "*.etl",
        "*.json",
        "*.log",
        "*.trace"
        "*.zip"
        )
    Properties = @{
        EventLogProviders = @(
            "Application"
            "System"
        )
        EtwTraceProviders = @{}
    }
}
