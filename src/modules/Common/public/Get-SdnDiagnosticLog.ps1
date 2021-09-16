# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnDiagnosticLog {
    <#
    .SYNOPSIS
        Collect the default enabled logs from SdnDiagnostics folder.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .PARAMETER FromDate
        Optional parameter that allows you to control how many hours worth of logs to retrieve from the system for the roles identified. Default is 4 hours.
        (Get-Date).AddHours(-4)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory,

        [parameter(Mandatory = $false)]
        [DateTime]$FromDate = (Get-Date).AddHours(-4)
    )

    try {
        $localLogDir = "C:\Windows\tracing\SDNDiagnostics\Logs"

        if (!(Test-Path -Path $localLogDir)) {
            "No SdnDiagnostics folder found, this need to run on SDN Infrastructure Nodes" | Trace-Output -Level:Warning
            return
        }

        "Collect SdnDiagnostics logs between {0} and {1}" -f $FromDate, (Get-Date) | Trace-Output -Verbose

        # Create local directory for SdnDiagnostics logs
        $logOutputDir = "$OutputDirectory\SdnDiagnostics"
        if (!(Test-Path -Path $logOutputDir -PathType Container)) {
            $null = New-Item -Path $logOutputDir -ItemType Directory
        }

        $sdnDiagLogs = Get-ChildItem -Path $localLogDir | Where-Object { $_.LastWriteTime -ge $FromDate }
        foreach ($sdnDiagLog in $sdnDiagLogs) {
            Copy-Item $sdnDiagLog.FullName -Destination $logOutputDir
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
