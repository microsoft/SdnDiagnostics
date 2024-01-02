# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

@{
    DefaultLogDirectory = "C:\Windows\Tracing\SDNDiagnostics\Logs"
    LogFileTypes = @("*.log", "*.etl", "*.cab")
    Properties = @{
        EventLogProviders = @(
            "Application"
            "System"
        )
        EtwTraceProviders = @{}
    }
}
