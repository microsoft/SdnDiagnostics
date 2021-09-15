# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Stop-NetshTrace {
    <#
    .SYNOPSIS
        Disables netsh tracing.
    #>
    
    try {
        $expression = Invoke-Expression -Command "netsh trace stop"
        if ($expression -ilike "*Tracing session was successfully stopped.*") {
            "Tracing was successfully stopped" | Trace-Output -Level:Verbose
            
            $object = New-Object -TypeName PSCustomObject -Property (
                [Ordered]@{
                    Status = 'Stopped'
                }
            )
        }
        elseif ($expression -ilike "*There is no trace session currently in progress.*") {
            "There is no trace session currently in progress" | Trace-Output -Level:Warning

            $object = New-Object -TypeName PSCustomObject -Property (
                [Ordered]@{
                    Status = 'Stopped'
                }
            )
        }
        else {
            # typically, the first line returned in scenarios where there was an error thrown will contain the error details
            $msg = $expression[0]
            throw New-Object System.Exception($msg)
        }

        return $object
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
