# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

enum SdnHealthResult {
    PASS
    FAIL
    WARNING
}

class SdnHealth {
    [SdnHealthResult]$Result
    [DateTime]$OccurrenceTime = [System.DateTime]::UtcNow
    [Object]$Properties
    [String]$Remediation
}
