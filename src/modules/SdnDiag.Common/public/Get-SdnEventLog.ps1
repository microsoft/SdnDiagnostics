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
        [ValidateSet('Common', 'Gateway', 'NetworkController', 'Server', 'LoadBalancerMux')]
        [String[]]$Role,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory,

        [parameter(Mandatory = $false)]
        [DateTime]$FromDate = (Get-Date).AddDays(-1),

        [Parameter(Mandatory = $false)]
        [DateTime]$ToDate = (Get-Date)
    )

    $fromDateUTC = $FromDate.ToUniversalTime()
    $toDateUTC = $ToDate.ToUniversalTime()
    [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath "EventLogs"
    $eventLogs = @()
    $eventLogProviders = @()

    "Collect event logs between {0} and {1} UTC" -f $fromDateUTC, $toDateUTC | Trace-Output
    if (-NOT (Initialize-DataCollection -FilePath $OutputDirectory.FullName -MinimumMB 200)) {
        "Unable to initialize environment for data collection" | Trace-Output -Level:Exception
        return
    }

    try {
        $Role | ForEach-Object {
            $roleConfig = Get-SdnModuleConfiguration -Role $_
            $eventLogProviders += $roleConfig.Properties.EventLogProviders
        }

        # check to see if the event log provider is valid
        # and that we have events to collect
        "Collect the following {0} events: {1}" -f $_, ($eventLogProviders -join ', ') | Trace-Output
        foreach ($provider in $eventLogProviders) {
            "Looking for event matching {0}" -f $provider | Trace-Output -Level:Verbose
            $eventLogsToAdd = Get-WinEvent -ListLog $provider -ErrorAction SilentlyContinue | Where-Object { $_.RecordCount }
            if ($eventLogsToAdd) {
                $eventLogs += $eventLogsToAdd
            }
            else {
                "No events found for {0}" -f $provider | Trace-Output
            }
        }

        # process each of the event logs identified
        # and export them to csv and evtx files
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
