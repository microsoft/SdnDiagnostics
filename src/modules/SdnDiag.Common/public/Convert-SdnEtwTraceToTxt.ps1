function Convert-SdnEtwTraceToTxt {
    <#
    .SYNOPSIS
        Used to convert existing etw (.etl) provider traces into text readable format
    .PARAMETER FileName
        ETL trace file path and name to convert
    .PARAMETER Destination
        Output file name and directory. If omitted, will use the FileName path and base name.
    .PARAMETER Overwrite
        Overwrites existing files. If omitted, defaults to no.
    .PARAMETER Report
        Generates an HTML report. If omitted, defaults to no.
    .EXAMPLE
        PS> Convert-SdnEtwTraceToTxt -FileName "C:\Temp\CSS_SDN\Trace.etl"
    .EXAMPLE
        PS> Convert-SdnEtwTraceToTxt -FileName "C:\Temp\CSS_SDN\Trace.etl" -Destination "C:\Temp\CSS_SDN_NEW\trace.txt"
    .EXAMPLE
        PS> Convert-SdnEtwTraceToTxt -FileName "C:\Temp\CSS_SDN\Trace.etl" -Overwrite Yes
    .EXAMPLE
        PS> Convert-SdnEtwTraceToTxt -FileName "C:\Temp\CSS_SDN\Trace.etl" -Report Yes
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript( {
            if ($_ -notmatch "(\.etl)") {
                throw "The file specified in the FileName argument must be etl extension"
            }
            return $true
        })]
        [System.String]$FileName,

        [Parameter(Mandatory = $false)]
        [System.String]$Destination,

        [Parameter(Mandatory = $false)]
        [ValidateSet('No', 'Yes')]
        [System.String]$Overwrite = 'No',

        [Parameter(Mandatory = $false)]
        [ValidateSet('No', 'Yes')]
        [System.String]$Report = 'No'
    )

    try {
        $fileInfo = Get-Item -Path $FileName -ErrorAction Stop

        if (-NOT $PSBoundParameters.ContainsKey('Destination')) {
            [System.String]$Destination = $fileInfo.DirectoryName
        }

        if (-NOT (Test-Path -Path $Destination -PathType Container)) {
            $null = New-Item -Path $Destination -ItemType Directory -Force
        }

        [System.String]$outputFile = "{0}.txt" -f (Join-Path -Path $Destination -ChildPath $fileInfo.BaseName)
        [System.String]$cmd = "netsh trace convert input={0} output={1} overwrite={2} report={3}" `
            -f $fileInfo.FullName, $outputFile, $Overwrite, $Report

        "Netsh trace cmd:`n`t{0}" -f $cmd | Trace-Output -Level:Verbose
        $expression = Invoke-Expression -Command $cmd

        # output returned is string objects, so need to manually do some mapping to correlate the properties
        # that can be then returned as psobject to the call
        if ($expression[5] -ilike "*done*") {
            $object = New-Object -TypeName PSCustomObject -Property (
                [Ordered]@{
                    Status = 'Success'
                    FileName = $outputFile
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
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
