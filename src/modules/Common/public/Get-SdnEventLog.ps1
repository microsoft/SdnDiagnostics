# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnEventLog {
    <#
    .SYNOPSIS
        Collect the Windows Event Logs for different SDN Roles
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .PARAMETER FromDate
        Optional parameter that allows you to control how many hours worth of logs to retrieve from the system for the roles identified. Default is 1 day.
        (Get-Date).AddDays(-1)
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnRoles]$Role,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory,

        [parameter(Mandatory = $false)]
        [DateTime]$FromDate = (Get-Date).AddDays(-1)
    )
    try {
        $config = Get-SdnRoleConfiguration -Role:NetworkController

        # ensure that the appropriate windows feature is installed and ensure module is imported
        $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
        if (!$confirmFeatures) {
            throw New-Object System.Exception("Required feature is missing")
        }

        # build array of win events based on which role the function is being executed
        # we will build these and dump the results at the end
        $eventLogs = [System.Collections.ArrayList]::new()
        $eventLogProviders = $config.properties.eventLogProviders
        foreach ($provider in $eventLogProviders) {
            "Looking for Event matching {0}" -f $provider | Trace-Output -Level:Verbose
            $eventLogsToAdd = Get-WinEvent -ListLog "$provider" | Where-Object { $_.RecordCount }
            if ($eventLogsToAdd.Count -gt 1) {
                [void]$eventLogs.AddRange($eventLogsToAdd)
            }
            elseif ($eventLogsToAdd.Count -gt 0) {
                [void]$eventLogs.Add($eventLogsToAdd)
            }
            else {
                "No Event match {0}" -f $provider | Trace-Output -Level:Warning
            }
        }

        # export the event logs in csv and evtx formats
        $eventLogFolder = "$OutputDirectory\EventLogs"
        if (!(Test-Path -Path $eventLogFolder -PathType Container)) {
            $null = New-Item -Path $eventLogFolder -ItemType Directory -Force
        }

        foreach ($eventLog in $eventLogs) {
            "Export Event log {0} to {1}" -f $eventLog.LogName, "$eventLogFolder\$($eventLog.LogName).csv".Replace("/", "_") | Trace-Output -Level:Verbose
            Get-WinEvent -LogName $eventLog.LogName `
            | Where-Object { $_.TimeCreated -gt $FromDate } `
            | Select-Object TimeCreated, LevelDisplayName, Id, ProviderName, ProviderID, TaskDisplayName, OpCodeDisplayName, Message `
            | Export-Csv -Path "$eventLogFolder\$($eventLog.LogName).csv".Replace("/", "_") -NoTypeInformation -Force
            wevtutil epl $eventLog.LogName "$eventLogFolder\$($eventLog.LogName).evtx".Replace("/", "_") /ow
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
