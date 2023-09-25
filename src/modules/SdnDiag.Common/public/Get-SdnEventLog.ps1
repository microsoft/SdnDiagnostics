function Get-SdnEventLog {
    <#
    .SYNOPSIS
        Collect the Windows Event Logs for different SDN Roles.
    .PARAMETER Role
        The specific SDN role to collect windows event logs from.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .PARAMETER FromDate
        Determines the start time of what logs to collect. If omitted, defaults to the last 1 day.
    .PARAMETER ToDate
        Determines the end time of what logs to collect. Optional parameter that if ommitted, defaults to current time.
    .EXAMPLE
        PS> Get-SdnEventLog -OutputDirectory "C:\Temp\CSS_SDN"
    .EXAMPLE
        PS> Get-SdnEventLog -OutputDirectory "C:\Temp\CSS_SDN" -FromDate (Get-Date).AddHours(-12)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnRoles]$Role,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory,

        [parameter(Mandatory = $false)]
        [DateTime]$FromDate = (Get-Date).AddDays(-1),

        [Parameter(Mandatory = $false)]
        [DateTime]$ToDate = (Get-Date)
    )

    $fromDateUTC = $FromDate.ToUniversalTime()
    $toDateUTC = $ToDate.ToUniversalTime()

    try {
        $roleConfig = Get-SdnModuleConfiguration -Role $Role.ToString()
        $eventLogs = [System.Collections.ArrayList]::new()
        [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath "EventLogs"

        "Collect event logs between {0} and {1} UTC" -f $fromDateUTC, $toDateUTC | Trace-Output

        if (-NOT (Initialize-DataCollection -Role $Role.ToString() -FilePath $OutputDirectory.FullName -MinimumGB 1)) {
            "Unable to initialize environment for data collection" | Trace-Output -Level:Exception
            return
        }

        $eventLogProviders = $roleConfig.Properties.EventLogProviders
        if ($null -ieq $eventLogs) {
            "No event log providers found for {0}" -f $Role.ToString() | Trace-Output -Level:Warning
            return
        }

        "Collect the following events: {0}" -f ($eventLogProviders -join ',') | Trace-Output

        # build array of win events based on which role the function is being executed
        # we will build these and dump the results at the end
        foreach ($provider in $eventLogProviders) {
            "Looking for event matching {0}" -f $provider | Trace-Output -Level:Verbose
            $eventLogsToAdd = Get-WinEvent -ListLog $provider -ErrorAction SilentlyContinue | Where-Object { $_.RecordCount }
            if ($eventLogsToAdd.Count -gt 1) {
                [void]$eventLogs.AddRange($eventLogsToAdd)
            }
            elseif ($eventLogsToAdd.Count -gt 0) {
                [void]$eventLogs.Add($eventLogsToAdd)
            }
            else {
                "No events found for {0}" -f $provider | Trace-Output
            }
        }

        foreach ($eventLog in $eventLogs) {
            $fileName = ("{0}\{1}" -f $OutputDirectory.FullName, $eventLog.LogName).Replace("/", "_")

            "Export event log {0} to {1}" -f $eventLog.LogName, $fileName | Trace-Output -Level:Verbose
            $events = Get-WinEvent -LogName $eventLog.LogName -ErrorAction SilentlyContinue `
            | Where-Object { $_.TimeCreated.ToUniversalTime() -gt $fromDateUTC -AND $_.TimeCreated -lt $toDateUTC }

            if ($events) {
                $events | Select-Object TimeCreated, LevelDisplayName, Id, ProviderName, ProviderID, TaskDisplayName, OpCodeDisplayName, Message `
                | Export-Csv -Path "$fileName.csv" -NoTypeInformation -Force
            }

            wevtutil epl $eventLog.LogName "$fileName.evtx" /ow:$true
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
