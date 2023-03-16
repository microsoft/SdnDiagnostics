# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

enum SdnHealthResult {
    PASS
    FAIL
    WARNING
}

class SdnHealth {
    [String]$Name = (Get-PSCallStack)[1].Command
    [SdnHealthResult]$Result
    [DateTime]$OccurrenceTime = [System.DateTime]::UtcNow
    [Object]$Properties
    [String]$Remediation
}
