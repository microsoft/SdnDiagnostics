function Test-ScheduledTaskEnabled {
    <#
    .SYNOPSIS
        Ensures the scheduled task responsible for etl compression is enabled and running
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()
    $array = @()

    $scriptBlock = {

        $object = [PSCustomObject]@{
            TaskName = 'SDN Diagnostics Task'
            State = $null
        }

        try {
            # check to see if logging is enabled on the registry key
            # if it is not, return the object with the state set to 'Logging Disabled'
            $isLoggingEnabled = Get-ItemPropertyValue -Path "HKLM:\Software\Microsoft\NetworkController\Sdn\Diagnostics\Parameters" -Name 'IsLoggingEnabled'
            if (-NOT $isLoggingEnabled ) {
                $object.State = 'Logging Disabled'
                return $object
            }

            $result = Get-ScheduledTask -TaskName 'SDN Diagnostics Task' -ErrorAction Stop
            if ($result) {
                $object.State = $result.State.ToString()
                return $object
            }
        }
        catch {
            # if the scheduled task does not exist, return the object with the state set to 'Not Found'
            $object.State = 'Not Found'
            return $object
        }
    }

    try {
        $scheduledTaskReady = Invoke-PSRemoteCommand -ComputerName $SdnEnvironmentObject.ComputerName -Credential $Credential -ScriptBlock $scriptBlock -AsJob -PassThru
        foreach ($result in $scheduledTaskReady) {
            switch ($result.State) {
                'Logging Disabled' {
                    "SDN Diagnostics Task is not available on {0} because logging is disabled." -f $result.PSComputerName | Trace-Output -Level:Verbose
                }
                'Not Found' {
                    "Unable to locate SDN Diagnostics Task on {0}." -f $result.PSComputerName | Trace-Output -Level:Error
                    $sdnHealthObject.Result = 'FAIL'
                }
                'Disabled' {
                    "SDN Diagnostics Task is disabled on {0}." -f $result.PSComputerName | Trace-Output -Level:Error
                    $sdnHealthObject.Result = 'FAIL'
                    $sdnHealthObject.Remediation += "Use 'Repair-SdnDiagnosticsScheduledTask' to enable the 'SDN Diagnostics Task' scheduled task on $($result.PSComputerName)."
                }
                default {
                    "SDN Diagnostics Task is {0} on {1}." -f $result.State, $result.PSComputerName | Trace-Output -Level:Verbose
                }
            }

            $array += [PSCustomObject]@{
                State = $result.State
                Computer = $result.PSComputerName
            }
        }

        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
    }
}
