# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Trace-Output {

    [CmdletBinding()]
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
    $computerName = $env:COMPUTERNAME

    # create custom object for formatting purposes
    $traceEvent = [PSCustomObject]@{
        Computer = $computerName
        TimestampUtc = [DateTime]::UtcNow.ToString()
        FunctionName = $callingFunction
        Level = $Level.ToString()
        Message = $Message
    }

    # write the message to the console
    switch($Level){
        'Error' {
            "[{0}] {1}" -f $computerName, $traceEvent.Message | Write-Error
        }

        'Success' {
            "[{0}] {1}" -f $computerName, $traceEvent.Message | Write-Host -ForegroundColor:Green
        }

        'Verbose' {
            if($VerbosePreference -ne [System.Management.Automation.ActionPreference]::SilentlyContinue) {
                "[{0}] {1}" -f $computerName, $traceEvent.Message | Write-Verbose
            }
        }

        'Warning' {
            "[{0}] {1}" -f $computerName, $traceEvent.Message | Write-Warning
        }

        default {
            "[{0}] {1}" -f $computerName, $traceEvent.Message | Write-Host -ForegroundColor:Cyan
        }
    }

    # write the event to trace file to be used for debugging purposes
    $traceEvent | Export-Csv -Append -NoTypeInformation -Path $traceFile.FullName
}
