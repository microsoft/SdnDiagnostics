function Repair-SdnDiagnosticsScheduledTask {
    <#
    .SYNOPSIS
        Repairs the SDN Diagnostics scheduled task.
    #>

    [CmdletBinding()]
    param()

    switch ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType) {
        'FailoverCluster' {
            $taskName = "FcDiagnostics"
        }
        'ServiceFabric' {
            $taskName = "SDN Diagnostics Task"
        }
    }

    try {
        $isLoggingEnabled = Get-ItemPropertyValue -Path "HKLM:\Software\Microsoft\NetworkController\Sdn\Diagnostics\Parameters" -Name 'IsLoggingEnabled'
        if (-NOT $isLoggingEnabled ) {
            "Logging is currently disabled. Logging must be enabled before the scheduled task can be repaired." | Trace-Output -Level:Warning
            return $null
        }

        $scheduledTask = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
        if ($scheduledTask) {
            # if the scheduled task is disabled, enable it and start it
            if ($scheduledTask.State -ieq "Disabled") {
                "Enabling scheduled task." | Trace-Output
                $scheduledTask | Enable-ScheduledTask -ErrorAction Stop

                "Starting scheduled task." | Trace-Output
                Get-ScheduledTask -TaskName $taskName | Start-ScheduledTask -ErrorAction Stop
            }
            else {
                "Scheduled task is already enabled." | Trace-Output
            }

            return (Get-ScheduledTask -TaskName $taskName)
        }
        else {
            "Scheduled task does not exist." | Trace-Output -Level:Warning
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
