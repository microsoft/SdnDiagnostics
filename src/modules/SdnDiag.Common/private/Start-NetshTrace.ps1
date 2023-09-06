function Start-NetshTrace {
    <#
    .SYNOPSIS
        Enables netsh tracing. Supports pre-configured trace providers or custom provider strings.
    .PARAMETER TraceProviderString
        The trace providers in string format that you want to trace on.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .PARAMETER MaxTraceSize
        Optional. Specifies the maximum size in MB for saved trace files. If unspecified, the default is 1024.
    .PARAMETER Capture
        Optional. Specifies whether packet capture is enabled in addition to trace events. If unspecified, the default is No.
    .PARAMETER Overwrite
        Optional. Specifies whether this instance of the trace conversion command overwrites files that were rendered from previous trace conversions. If unspecified, the default is Yes.
    .PARAMETER Correlation
        Optional. Specifies whether related events will be correlated and grouped together. If unspecified, the default is No.
    .PARAMETER Report
        Optional. Specifies whether a complementing report will be generated in addition to the trace file report. If unspecified, the default is disabled.
    .EXAMPLE
        PS> Start-NetshTrace -OutputDirectory "C:\Temp\CSS_SDN" -Capture Yes
    .EXAMPLE
        PS> Start-NetshTrace -OutputDirectory "C:\Temp\CSS_SDN" -TraceProviderString 'provider="{EB171376-3B90-4169-BD76-2FB821C4F6FB}" level=0xff' -Capture No
    .EXAMPLE
        PS> Start-NetshTrace -OutputDirectory "C:\Temp\CSS_SDN" -TraceProviderString 'provider="{EB171376-3B90-4169-BD76-2FB821C4F6FB}" level=0xff' -Capture Yes
    .EXAMPLE
        PS> Start-NetshTrace -OutputDirectory "C:\Temp\CSS_SDN" -Capture Yes -MaxTraceSize 2048 -Report Disabled
    .EXAMPLE
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [System.String]$TraceProviderString,

        [Parameter(Mandatory = $false)]
        [int]$MaxTraceSize = 1024,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Yes', 'No')]
        [System.String]$Capture = 'No',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Yes', 'No')]
        [System.String]$Overwrite = 'Yes',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Enabled', 'Disabled')]
        [System.String]$Report = 'Disabled',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Yes', 'No')]
        [System.String]$Correlation = 'No'
    )

    try {
        # ensure that we at least are attempting to configure NDIS tracing or ETW provider tracing, else the netsh
        # command will return a generic exception that is not useful to the operator
        if ($Capture -ieq 'No' -and !$TraceProviderString) {
            throw New-Object System.Exception("You must at least specify Capture or TraceProviderString parameter")
        }

        # ensure that the directory exists and specify the trace file name
        if (!(Test-Path -Path $OutputDirectory.FullName -PathType Container)) {
            $null = New-Item -Path $OutputDirectory.FullName -ItemType Directory -Force
        }
        $traceFile = "{0}\{1}_{2}_netshTrace.etl" -f $OutputDirectory.FullName, $env:COMPUTERNAME, (Get-FormattedDateTimeUTC)

        # enable the network trace
        if ($TraceProviderString) {
            $cmd = "netsh trace start capture={0} {1} tracefile={2} maxsize={3} overwrite={4} report={5} correlation={6}" `
                -f $Capture, $TraceProviderString, $traceFile, $MaxTraceSize, $Overwrite, $Report, $Correlation
        }
        else {
            $cmd = "netsh trace start capture={0} tracefile={1} maxsize={2} overwrite={3} report={4}, correlation={5}" `
                -f $Capture, $traceFile, $MaxTraceSize, $Overwrite, $Report, $Correlation
        }

        "Starting netsh trace" | Trace-Output
        "Netsh trace cmd:`n`t{0}" -f $cmd | Trace-Output -Level:Verbose

        $expression = Invoke-Expression -Command $cmd
        if ($expression -ilike "*Running*") {
            $object = New-Object -TypeName PSCustomObject -Property (
                [Ordered]@{
                    Status   = 'Running'
                    FileName = $traceFile
                }
            )
        }
        elseif ($expression -ilike "*A tracing session is already in progress*") {
            "A tracing session is already in progress" | Trace-Output -Level:Warning

            $object = New-Object -TypeName PSCustomObject -Property (
                [Ordered]@{
                    Status = 'Running'
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
