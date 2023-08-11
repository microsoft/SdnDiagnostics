function Get-SdnDiagnosticLogFile {
    <#
    .SYNOPSIS
        Collect the default enabled logs from SdnDiagnostics folder.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .PARAMETER FromDate
        Optional parameter that allows you to control how many hours worth of logs to retrieve from the system for the roles identified. Default is 4 hours.
    .PARAMETER ConvertETW
        Optional parameter that allows you to specify if .etl trace should be converted. By default, set to $true
    .EXAMPLE
        PS> Get-SdnDiagnosticLogFile -OutputDirectory "C:\Temp\CSS_SDN"
    .EXAMPLE
        PS> Get-SdnDiagnosticLogFile -OutputDirectory "C:\Temp\CSS_SDN" -FromDate (Get-Date).AddHours(-8)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$LogDir,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [DateTime]$FromDate = (Get-Date).AddHours(-4),

        [Parameter(Mandatory = $false)]
        [DateTime]$ToDate = (Get-Date),

        [Parameter(Mandatory = $false)]
        [bool]$ConvertETW = $true
    )

    $fromDateUTC = $FromDate.ToUniversalTime()
    $toDateUTC = $ToDate.ToUniversalTime()

    try {
        "Collect diagnostic logs in {0} between {1} and {2} UTC" -f $LogDir, $fromDateUTC, $toDateUTC | Trace-Output
        $commonConfig = Get-SdnModuleConfiguration -Role 'Common'
        # enumerate the log files in the log directory and filter based on the from and to date
        if (-NOT (Test-Path -Path $LogDir)) {
            "{0} does not exist" -f $LogDir | Trace-Output
            return
        }

        $logFiles = Get-ChildItem -Path "$LogDir\*" -Include $commonConfig.LogFileTypes -ErrorAction SilentlyContinue `
        | Where-Object { $_.LastWriteTime.ToUniversalTime() -ge $fromDateUTC -and $_.LastWriteTime.ToUniversalTime() -le $toDateUTC }
        if($null -eq $logFiles){
            "No log files found under {0} between {1} and {2} UTC." -f $LogDir, $fromDateUTC, $toDateUTC | Trace-Output
            return
        }

        # we want to call the initialize datacollection after we have identify the amount of disk space we will need to create a copy of the logs
        $minimumDiskSpace = [float](Get-FolderSize -FileName $logFiles.FullName -Total).GB * 3.5
        if (-NOT (Initialize-DataCollection -FilePath $OutputDirectory.FullName -MinimumGB $minimumDiskSpace)) {
            "Unable to initialize environment for data collection" | Trace-Output -Level:Exception
            return
        }

        # copy the log files from the default log directory to the output directory
        "Copying {0} files to {1}" -f $logFiles.Count, $OutputDirectory.FullName | Trace-Output
        Copy-Item -Path $logFiles.FullName -Destination $OutputDirectory.FullName -Force

        # convert the most recent etl trace file into human readable format without requirement of additional parsing tools
        if ($ConvertETW) {
            $convertFile = Get-Item -Path "$($OutputDirectory.FullName)\*" -Include '*.etl' | Sort-Object -Property LastWriteTime | Select-Object -Last 1
            if ($convertFile) {
                $null = Convert-SdnEtwTraceToTxt -FileName $convertFile.FullName -Overwrite 'Yes'
            }
        }

        # once we have copied the files to the new location we want to compress them to reduce disk space
        # if confirmed we have a .zip file, then remove the staging folder
        "Compressing results to {0}" -f "$($OutputDirectory.FullName).zip" | Trace-Output -Level:Verbose
        Compress-Archive -Path "$($OutputDirectory.FullName)\*" -Destination $OutputDirectory.FullName -CompressionLevel Optimal -Force
        if (Test-Path -Path "$($OutputDirectory.FullName).zip" -PathType Leaf) {
            Remove-Item -Path $OutputDirectory.FullName -Force -Recurse
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
