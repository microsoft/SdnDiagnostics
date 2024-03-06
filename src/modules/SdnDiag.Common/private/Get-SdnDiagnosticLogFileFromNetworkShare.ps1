function Get-SdnDiagnosticLogFileFromNetworkShare {
    <#
        .SYNOPSIS
            Collects diagnostic logs from a network share
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if ($_.contains("\\") -and $_.contains("\")) {
                return $true
            }
            else {
                throw "The network share path must be in the format of \\server\share"
            }
        })]
        [System.String]$NetworkSharePath,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [DateTime]$FromDate = (Get-Date).AddHours(-4),

        [Parameter(Mandatory = $false)]
        [DateTime]$ToDate = (Get-Date),

        [Parameter(Mandatory = $false)]
        [string[]]$NetworkControllerNodeNames,

        [Parameter(Mandatory = $false)]
        [string[]]$FilterByNode
    )

    $fromDateUTC = $FromDate.ToUniversalTime()
    $toDateUTC = $ToDate.ToUniversalTime()
    $outDir = Join-Path -Path $OutputDirectory.FullName -ChildPath 'NetShare_SdnDiagnosticLogs'

    try {
        $commonConfig = Get-SdnModuleConfiguration -Role 'Common'

        # service fabric logs for network controller will be stored in the root of the network share
        # so we want to add the NetBIOS names of the network controller nodes to the common configuration
        if ($NetworkControllerNodeNames) {
            $NetworkControllerNodeNames | ForEach-Object {
                $commonConfig.NetworkShareFolders += (Get-ComputerNameFQDNandNetBIOS -ComputerName $_).ComputerNameNetBIOS
            }
        }

        # if we have a filter by node, we want to filter the network share folders based on the NetBIOS name
        if ($FilterByNode) {
            $filterArray = @()

            $FilterByNode | ForEach-Object {
                $filterArray += (Get-ComputerNameFQDNandNetBIOS -ComputerName $_).ComputerNameNetBIOS
            }
        }

        "Creating new drive mapping to {0}" -f $NetworkSharePath | Trace-Output

        # create a new drive mapping to the network share path
        # if the credential is empty, we will not use a credential
        if ($Credential -eq [System.Management.Automation.PSCredential]::Empty) {
            $null = New-PSDrive -Name "SdnDiag_NetShare_Logs" -PSProvider FileSystem -Root $NetworkSharePath -ErrorAction Stop
        }
        else {
            $null = New-PSDrive -Name "SdnDiag_NetShare_Logs" -PSProvider FileSystem -Root $NetworkSharePath -Credential $Credential -ErrorAction Stop
        }

        "Collect diagnostic logs in {0} between {1} and {2} UTC" -f $NetworkSharePath, $fromDateUTC, $toDateUTC | Trace-Output

        # enumerate the current folders and filter based on the common configuration
        $folders = Get-ChildItem -Path $NetworkSharePath -Directory -ErrorAction Stop | Where-Object { $_.Name -iin $commonConfig.NetworkShareFolders }
        if ($null -ieq $folders) {
            "No folders found under {0}" -f $NetworkSharePath | Trace-Output -Level:Error
            return $null
        }

        $folders | ForEach-Object {
            $folder = [PSCustomObject]@{
                Name     = $_.Name
                FullName = $_.FullName
            }

            # for each of the log file types, we will enumerate the files
            # and filter them based on the from and to date
            $commonConfig.LogFileTypes | ForEach-Object {
                $logFiles = @()
                $logFileType = $_
                $getItemParams = @{
                    Path         = $folder.FullName
                    Filter       = $logFileType
                    Recurse      = $true
                    ErrorAction  = 'SilentlyContinue'
                }

                if ($filterArray) {
                    $filterArray | ForEach-Object {
                        $nodeNameFilter = $_
                        $unfilteredlogFiles = Get-ChildItem @getItemParams | Where-Object { $_.LastWriteTime.ToUniversalTime() -ge $fromDateUTC -and $_.LastWriteTime.ToUniversalTime() -le $toDateUTC }
                        $logFiles += $unfilteredlogFiles | Where-Object { $_.DirectoryName -ilike "*$nodeNameFilter*" }
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
                        [string]$outputPath = Join-Path -Path $outDir -ChildPath $_.Name.Substring($splitIndex)

                        # we want to call the initialize datacollection after we have identify the amount of disk space we will need to create a copy of the logs
                        # once the disk space is identified, we will initialize the data collection and copy the files to the output directory
                        $minimumDiskSpace = [float](Get-FolderSize -FileName $logFiles.FullName -Total).GB * 3.5
                        if (-NOT (Initialize-DataCollection -FilePath $outputPath -MinimumGB $minimumDiskSpace)) {
                            "Unable to copy files from {0} to {1}" -f $_.Name, $outputPath | Trace-Output -Level:Error
                        }
                        else {
                            "Copying {0} files to {1}" -f $_.Group.Count, $outputPath | Trace-Output
                            $_.Group | Copy-Item -Destination $outputPath -Force -ErrorAction Continue
                        }
                    }
                }
            }
        }

        # once we have copied the files to the new location we want to compress them to reduce disk space
        # if confirmed we have a .zip file, then remove the staging folder
        "Compressing results to {0}" -f "$outDir.zip" | Trace-Output
        Compress-Archive -Path "$outDir\*" -Destination $outDir -CompressionLevel Optimal -Force
        if (Test-Path -Path "$outDir.zip" -PathType Leaf) {
            Clear-SdnWorkingDirectory -Path $outDir -Force -Recurse
        }
    }
    catch {
        $_ | Trace-Exception
    }
}
