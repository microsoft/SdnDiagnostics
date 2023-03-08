class SdnHealthResult {
    [SdnHealthResult]$Result
    [DateTime]$OccurrenceTime = [System.DateTime]::UtcNow
    [Object]$Properties
    [String]$Remediation
}
