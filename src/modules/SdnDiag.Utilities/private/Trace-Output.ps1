function Trace-Output {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.String]$Message,

        [Parameter(Mandatory = $false)]
        [TraceLevel]$Level
    )

    begin {
        if (!$PSBoundParameters.ContainsKey('Level')) {
            $Level = [TraceLevel]::Information
        }

        $traceFile = (Get-TraceOutputFile)
        if ([string]::IsNullOrEmpty($traceFile)) {
            New-WorkingDirectory

            $traceFile = (Get-TraceOutputFile)
        }
    }
    process {
        # create custom object for formatting purposes
        $traceEvent = [PSCustomObject]@{
            Computer = $env:COMPUTERNAME.ToUpper().ToString()
            TimestampUtc = [DateTime]::UtcNow.ToString('yyyy-MM-dd HH-mm-ss')
            FunctionName = (Get-PSCallStack)[1].Command
            Level = $Level.ToString()
            Message = $Message
        }

        # write the message to the console
        switch($Level){
            'Error' {
                "[{0}] {1}" -f $traceEvent.Computer, $traceEvent.Message | Write-Error
            }

            'Exception' {
                "[{0}] {1}" -f $traceEvent.Computer, $traceEvent.Message | Write-Host -ForegroundColor:Red
            }

            'Success' {
                "[{0}] {1}" -f $traceEvent.Computer, $traceEvent.Message | Write-Host -ForegroundColor:Green
            }

            'Verbose' {
                if($VerbosePreference -ne [System.Management.Automation.ActionPreference]::SilentlyContinue) {
                    "[{0}] {1}" -f $traceEvent.Computer, $traceEvent.Message | Write-Verbose
                }
            }

            'Warning' {
                "[{0}] {1}" -f $traceEvent.Computer, $traceEvent.Message | Write-Warning
            }

            default {
                "[{0}] {1}" -f $traceEvent.Computer, $traceEvent.Message | Write-Host -ForegroundColor:Cyan
            }
        }

        # write the event to trace file to be used for debugging purposes
        $mutexInstance = Wait-OnMutex -MutexId 'SDN_TraceLogging' -ErrorAction Continue
        if ($mutexInstance) {
            $traceEvent | Export-Csv -Append -NoTypeInformation -Path $traceFile.FullName
        }
    }
    end {
        if ($mutexInstance) {
            $mutexInstance.ReleaseMutex()
        }
    }
}
