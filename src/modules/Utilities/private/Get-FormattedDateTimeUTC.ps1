function Get-FormattedDateTimeUTC {
    return ([DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))
}