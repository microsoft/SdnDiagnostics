function Get-SdnDiagnosticLogFile {
    <#
    .SYNOPSIS
        Collect the default enabled logs from SdnDiagnostics folder.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .PARAMETER FromDate
        Determines the start time of what logs to collect. If omitted, defaults to the last 4 hours.
    .PARAMETER ToDate
        Determines the end time of what logs to collect. Optional parameter that if ommitted, defaults to current time.
    .PARAMETER ConvertETW
        Optional parameter that allows you to specify if .etl trace should be converted. By default, set to $true
    .EXAMPLE
        PS> Get-SdnDiagnosticLogFile -LogDir "C:\Windows\Tracing\SdnDiagnostics" -OutputDirectory "C:\Temp\CSS_SDN"
    .EXAMPLE
        PS> Get-SdnDiagnosticLogFile -LogDir "C:\Windows\Tracing\SdnDiagnostics" -FromDate (Get-Date).AddHours(-1)
    .EXAMPLE
        PS> Get-SdnDiagnosticLogFile -LogDir "C:\Windows\Tracing\SdnDiagnostics" -FromDate '2023-08-11 10:00:00 AM' -ToDate '2023-08-11 11:30:00 AM'
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String[]]$LogDir,

        [Parameter(Mandatory = $true)]
        [System.IO.DirectoryInfo]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [DateTime]$FromDate = (Get-Date).AddHours(-4),

        [Parameter(Mandatory = $false)]
        [DateTime]$ToDate = (Get-Date),

        [Parameter(Mandatory = $false)]
        [bool]$ConvertETW = $true,

        [Parameter(Mandatory = $false)]
        [bool]$CleanUpFiles = $false,

        [Parameter(Mandatory = $false)]
        [string[]]$FolderNameFilter
    )

    begin {
        $fromDateUTC = $FromDate.ToUniversalTime()
        $toDateUTC = $ToDate.ToUniversalTime()
        $commonConfig = Get-SdnModuleConfiguration -Role 'Common'
    }

    process {
        $LogDir | ForEach-Object {
            $folder = Get-Item -Path $_ -ErrorAction SilentlyContinue

            # if the folder is not found, then log a message and continue to the next folder
            if ($null -ieq $folder) {
                "Unable to locate {0}" -f $_ | Trace-Output -Level:Verbose
                return
            }

            $logFiles = @()
            $getItemParams = @{
                Path         = $folder.FullName
                Include      = $commonConfig.LogFileTypes
                Recurse      = $true
                ErrorAction  = 'SilentlyContinue'
            }

            "Scanning for {0} in {1} between {2} and {3} UTC" -f ($commonConfig.LogFileTypes -join ', '), $folder.FullName, $fromDateUTC, $toDateUTC | Trace-Output -Level:Verbose
            if ($FolderNameFilter) {
                $FolderNameFilter | ForEach-Object {
                    [string]$filter = $_
                    $unfilteredlogFiles = Get-ChildItem @getItemParams | Where-Object { $_.LastWriteTime.ToUniversalTime() -ge $fromDateUTC -and $_.LastWriteTime.ToUniversalTime() -le $toDateUTC }

                    if ($unfilteredlogFiles) {
                        "Filtering logs related to DirectoryName contains '{0}'" -f $filter | Trace-Output -Level:Verbose
                        $logFiles += $unfilteredlogFiles | Where-Object { $_.DirectoryName -ilike "*$filter*" }
                    }
                }
            }
            else {
                $logFiles += Get-ChildItem @getItemParams | Where-Object { $_.LastWriteTime.ToUniversalTime() -ge $fromDateUTC -and $_.LastWriteTime.ToUniversalTime() -le $toDateUTC }
            }

            if ($logFiles) {
                # enumerate the group of log files based on the directory
                # and then create a dynamic directory based on the folder name in an effort to preserve the original directory structure
                $logDirectory = $logFiles | Group-Object -Property Directory
                $logDirectory | ForEach-Object {
                    $splitIndex = $_.Name.IndexOf($folder.Name)
                    [System.IO.DirectoryInfo]$outputPath = Join-Path -Path $OutputDirectory.FullName -ChildPath $_.Name.Substring($splitIndex)

                    # we want to call the initialize datacollection after we have identify the amount of disk space we will need to create a copy of the logs
                    # once the disk space is identified, we will initialize the data collection and copy the files to the output directory
                    $minimumDiskSpace = [float](Get-FolderSize -FileName $logFiles.FullName -Total).GB * 3.5
                    if (-NOT (Initialize-DataCollection -FilePath $outputPath.FullName -MinimumGB $minimumDiskSpace)) {
                        "Unable to copy files from {0} to {1}" -f $_.Name, $outputPath.FullName | Trace-Output -Level:Error
                        continue
                    }
                    else {
                        "Copying {0} files to {1}" -f $_.Group.Count, $outputPath.FullName | Trace-Output
                        $_.Group | Copy-Item -Destination $outputPath.FullName -Force -ErrorAction Continue
                    }

                    # convert the most recent etl trace file into human readable format without requirement of additional parsing tools
                    if ($ConvertETW) {
                        $convertFile = Get-ChildItem -Path $outputPath.FullName -Include '*.etl' -Recurse | Sort-Object -Property LastWriteTime | Select-Object -Last 1
                        if ($convertFile) {
                            $null = Convert-SdnEtwTraceToTxt -FileName $convertFile.FullName -Overwrite 'Yes'
                        }
                    }

                    try {
                        # compress the files into a single zip file
                        "Compressing results to {0}.zip" -f $outputPath.FullName | Trace-Output
                        Compress-Archive -Path "$($outputPath.FullName)\*" -Destination "$($outputPath.FullName).zip" -CompressionLevel Optimal -Force

                        # once we have copied the files to the new location we want to compress them to reduce disk space
                        # if confirmed we have a .zip file, then remove the staging folder
                        if (Test-Path -Path "$($outputPath.FullName).zip" -PathType Leaf) {
                            Clear-SdnWorkingDirectory -Path $outputPath.FullName -Force -Recurse
                        }

                        # if we opted to clean up the files, then proceed to do so now
                        if ($CleanUpFiles) {
                            "Cleaning up files" | Trace-Output -Level:Verbose
                            Clear-SdnWorkingDirectory -Path $logFiles.FullName -Force -Recurse
                        }
                    }
                    catch {
                        "Unable to compress files to {0}" -f "$($folder.FullName).zip" | Trace-Output -Level:Error
                    }
                }
            }
            else {
                "No log files found under {0} between {1} and {2} UTC." -f $folder.FullName, $fromDateUTC, $toDateUTC | Trace-Output -Level:Verbose
            }
        }
    }
}
