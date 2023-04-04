function Test-ScheduledTaskEnabled {
    <#
    .SYNOPSIS
        Ensures the scheduled task responsible for etl compression is enabled and running
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricHealthObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()
    $array = @()

    $scriptBlock = {
        try {
            $result = Get-ScheduledTask -TaskName 'SDN Diagnostics Task' -ErrorAction Stop
            return [PSCustomObject]@{
                TaskName = $result.TaskName
                State = $result.State
            }
        }
        catch {
            return [PSCustomObject]@{
                TaskName = 'SDN Diagnostics Task'
                State = 'Not Available'
            }
        }
    }

    try {
        $scheduledTaskReady = Invoke-PSRemoteCommand -ComputerName $SdnEnvironmentObject.ComputerName -Credential $Credential -ScriptBlock $scriptBlock -AsJob -PassThru
        foreach ($result in $scheduledTaskReady) {
            if ($result.State -ine 'Running') {
                "SDN Diagnostics Task state is {1} on {1}, which may result in uncontrolled log growth" -f $result.State, $result.PSComputerName | Trace-Output -Level:Warning
                $sdnHealthObject.Result = 'FAIL'
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
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
