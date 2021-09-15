# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Convert-EtwTraceToTxt {
    <#
    .SYNOPSIS
        Used to convert existing etw provider traces into text readable format
    .PARAMETER FileName
        ETL trace file path and name to convert 
    .PARAMETER Destination
        Output file name and directory. If ommitted, will use the FileName path and base name.
    .PARAMETER Overwrite
        Overwrites existing files. If ommitted, defaults to no.
    .PARAMETER Report
        Generates an HTML report. If ommitted, defaults to no.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$FileName,

        [Parameter(Mandatory = $false)]
        [System.IO.FileInfo]$Destination,

        [Parameter(Mandatory = $false)]
        [ValidateSet('No', 'Yes')]
        [System.String]$Overwrite = 'No',

        [Parameter(Mandatory = $false)]
        [ValidateSet('No', 'Yes')]
        [System.String]$Report = 'No'
    )

    try {
        if (!$Destination) {
            [System.IO.FileInfo]$Destination = $FileName.FullName
        }

        if (!(Test-Path -Path $Destination.FullName -PathType Container)) {
            $null = New-Item -Path $Destination.FullName -ItemType Directory -Force
        }

        [System.String]$outputFile = "{0}.txt" -f (Join-Path -Path $Destination.FullName -ChildPath $FileName.BaseName)
        [System.String]$cmd = "netsh trace convert input={0} output={1} overwrite={2} report={3}" `
            -f $FileName.FullName, $outputFile, $Overwrite, $Report
        
        "Netsh trace cmd:`n`t{0}" -f $cmd | Trace-Output -Level:Verbose    
        $expression = Invoke-Expression -Command $cmd

        # output returned is string objects, so need to manually do some mapping to correlate the properties
        # that can be then returned as psobject to the call
        if ($expression[5] -ilike "*done*") {
            $object = New-Object -TypeName PSCustomObject -Property (
                [Ordered]@{
                    Status = 'Success'
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