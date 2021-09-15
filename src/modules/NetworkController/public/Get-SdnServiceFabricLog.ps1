function Get-SdnServiceFabricLog {
    <#
    .SYNOPSIS
        Collect the default enabled logs from Service Fabric folder
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .PARAMETER FromDate
        Optional parameter that allows you to control how many hours worth of logs to retrieve from the system for the roles identified. Default is 120 hours.
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
        $localLogDir = "C:\ProgramData\Microsoft\Service Fabric\log\Traces"

        if (!(Test-Path -Path $localLogDir)) {
            "No Service Farbci Traces folder found at {0}, this need to run on Network Controller" -f $localLogDir | Trace-Output -Level:Warning
            return
        }

        "Collect Service Fabric logs between {0} and {1}" -f $FromDate, (Get-Date) | Trace-Output -Verbose

        # Create local directory for ServiceFabricTraces logs
        $logOutputDir = "$OutputDirectory\ServiceFabricTraces"
        if (!(Test-Path -Path $logOutputDir -PathType Container)) {
            $null = New-Item -Path $logOutputDir -ItemType Directory
        }

        $serviceFabricLogs = Get-ChildItem -Path $localLogDir | Where-Object { $_.LastWriteTime -ge $FromDate }
        foreach ($serviceFabricLog in $serviceFabricLogs) {
            Copy-Item $serviceFabricLog.FullName -Destination $logOutputDir
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
