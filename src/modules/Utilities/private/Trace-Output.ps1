function Trace-Output {
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.String]$Message,

        [Parameter(Mandatory = $false)]
        [TraceLevel]$Level
    )

    if(!$PSBoundParameters.ContainsKey('Level')) {
        $Level = [TraceLevel]::Information
    }  

    # Verify we've made the working directory and trace file
    if([string]::IsNullOrEmpty((Get-TraceOutputFile))){
        New-WorkingDirectory
    }

    $traceFile = (Get-TraceOutputFile)
    $callingFunction = (Get-PSCallStack)[1].Command

    # create custom object for formatting purposes
    $traceEvent = [PSCustomObject]@{
        TimestampUtc = [DateTime]::UtcNow.ToString()
        FunctionName = $callingFunction
        Level = $Level.ToString()
        Message = $Message
    }

    # write the message to the console
    switch($Level){
        'Error' {
            $traceEvent.Message | Write-Host -ForegroundColor:Red
        }

        'Success' {
            $traceEvent.Message | Write-Host -ForegroundColor:Green
        }

        'Verbose' {
            if($VerbosePreference -ne [System.Management.Automation.ActionPreference]::SilentlyContinue) {
                $traceEvent.Message | Write-Verbose
            }
        }

        'Warning' {
            $traceEvent.Message | Write-Host -ForegroundColor:Yellow
        }
        
        default {
            $traceEvent.Message | Write-Host -ForegroundColor:Cyan
        }
    }

    # write the event to trace file to be used for debugging purposes
    $traceEvent | Export-Csv -Append -NoTypeInformation -Path $traceFile.FullName
}