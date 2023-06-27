# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

enum SdnHealthResult {
    PASS
    FAIL
    WARNING
}

class SdnHealth {
    [String]$Name = (Get-PSCallStack)[1].Command
    [SdnHealthResult]$Result = 'PASS'
    [DateTime]$OccurrenceTime = [System.DateTime]::UtcNow
    [Object]$Properties
    [String[]]$Remediation
}

class SdnFabricEnvObject {
    [String[]]$ComputerName
    [Uri]$NcUrl
    [Object]$Role
    [Object]$EnvironmentInfo
}

class SdnFabricHealthReport {
    [DateTime]$OccurrenceTime = [System.DateTime]::UtcNow
    [String]$Role
    [SdnHealthResult]$Result = 'PASS'
    [Object[]]$HealthValidation
}
