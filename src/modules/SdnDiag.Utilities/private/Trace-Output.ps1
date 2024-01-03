function Trace-Output {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.String]$Message,

        [Parameter(Mandatory = $false)]
        [TraceLevel]$Level,

        [parameter(Mandatory = $false)]
        $Exception
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

        $formattedMessage = "[{0}] {1}" -f $traceEvent.Computer, $traceEvent.Message

        # write the message to the console
        switch($Level){
            'Error' {
                $formattedMessage | Write-Host -ForegroundColor:Red
            }

            'Exception' {
                Write-Error -Exception $Exception.Exception -Message $formattedMessage
                if ($Exception) {
                    $traceEvent.FunctionName = (Get-PSCallStack)[2].Command
                    $traceEvent | Add-Member -MemberType NoteProperty -Name 'ScriptStackTrace' -Value $Exception.ScriptStackTrace
                }
            }

            'Success' {
                $formattedMessage  | Write-Host -ForegroundColor:Green
            }

            'Verbose' {
                if($VerbosePreference -ne [System.Management.Automation.ActionPreference]::SilentlyContinue) {
                    $formattedMessage | Write-Verbose
                }
            }

            'Warning' {
                $formattedMessage | Write-Warning
            }

            default {
                $formattedMessage | Write-Host -ForegroundColor:Cyan
            }
        }

        # write the event to trace file to be used for debugging purposes
        $mutexInstance = Wait-OnMutex -MutexId 'SDN_TraceLogging' -ErrorAction Continue
        if ($mutexInstance) {
            $traceEvent | Export-Csv -Append -NoTypeInformation -Path $traceFile
        }
    }
    end {
        if ($mutexInstance) {
            $mutexInstance.ReleaseMutex()
        }
    }
}
