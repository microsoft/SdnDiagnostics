function Start-EtwTraceSession {
    <#
    .SYNOPSIS
        Start the ETW trace with TraceProviders included.
    .PARAMETER TraceName
        The trace name to identify the ETW trace session
    .PARAMETER TraceProviders
        The trace providers in string format that you want to trace on
    .PARAMETER TraceFile
        The trace file that will be written.
    .PARAMETER MaxTraceSize
        Optional. Specifies the maximum size in MB for saved trace files. If unspecified, the default is 1024.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TraceName,

        [Parameter(Mandatory = $true)]
        [string[]]$TraceProviders,

        [Parameter(Mandatory = $true)]
        [ValidateScript( {
                if ($_ -notmatch "(\.etl)") {
                    throw "The file specified in the TraceFile argument must be etl extension"
                }
                return $true
            })]
        [System.IO.FileInfo]$TraceFile,

        [Parameter(Mandatory = $false)]
        [int]$MaxTraceSize = 1024
    )

    try {
        # ensure that the directory exists for file path
        if (!(Test-Path -Path (Split-Path -Path $TraceFile.FullName -Parent) -PathType Container)) {
            $null = New-Item -Path (Split-Path -Path $TraceFile.FullName -Parent) -ItemType Directory -Force
        }

        $logmanCmd = "logman create trace $TraceName -ow -o $TraceFile -nb 16 16 -bs 1024 -mode Circular -f bincirc -max $MaxTraceSize -ets"
        $result = Invoke-Expression -Command $logmanCmd

        # Session create failure error need to be reported to user to be aware, this means we have one trace session missing.
        # Provider add failure might be ignored and exposed via verbose trace/log file only to debug.
        if ("$result".Contains("Error")) {
            "Create session {0} failed with error {1}" -f $TraceName, "$result" | Trace-Output -Level:Warning
        }
        else {
            "Created session {0} with result {1}" -f $TraceName, "$result" | Trace-Output -Level:Verbose
        }

        foreach ($provider in $TraceProviders) {
            $logmanCmd = 'logman update trace $TraceName -p "$provider" 0xffffffffffffffff 0xff -ets'
            $result = Invoke-Expression -Command $logmanCmd
            "Added provider {0} with result {1}" -f $provider, "$result" | Trace-Output -Level:Verbose
        }
    }
    catch {
        $_ | Trace-Exception
    }
}
