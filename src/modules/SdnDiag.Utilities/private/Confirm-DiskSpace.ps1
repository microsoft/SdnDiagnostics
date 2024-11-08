function Confirm-DiskSpace {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'GB')]
        [Parameter(Mandatory = $false, ParameterSetName = 'MB')]
        [System.String]$FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'GB')]
        $MinimumGB,

        [Parameter(Mandatory = $true, ParameterSetName = 'MB')]
        $MinimumMB
    )

       # try cluster first, then local machine
       try 
       {
           
           $csvs = Get-ClusterSharedVolume | Select-Object SharedVolumeInfo
           if ($null -ne $csvs) {
               foreach($csv in $csvs) 
               {
                   if(-not [string]::IsNullOrEmpty(($csv.SharedVolumeInfo.FriendlyVolumeName)) -and  `
                           $null -ne $csv.SharedVolumeInfo.Partition -and `
                           $FilePath.StartsWith($csv.SharedVolumeInfo.FriendlyVolumeName, [System.StringComparison]::OrdinalIgnoreCase) -and `
                           (($csv.SharedVolumeInfo.Partition.FreeSpace/1GB -gt $MinimumGB) -and ($csv.SharedVolumeInfo.Partition.FreeSpace/1MB -gt $MinimumMB)))
                   {
                       "Required: {0} GB | Available: {1} GB" -f ([float]$MinimumGB).ToString(), $($csv.SharedVolumeInfo.Partition.FreeSpace/1GB)  | Trace-Output -Level:Verbose
                       return $true
                   }
               }
           }
       }
       catch
       { }

    [System.Char]$driveLetter = (Split-Path -Path $FilePath -Qualifier).Replace(':','')

    $drive = Get-PSDrive $DriveLetter -ErrorAction Stop
    if ($null -eq $drive) {
        throw New-Object System.NullReferenceException("Unable to retrieve PSDrive information")
    }

    $freeSpace = Format-ByteSize -Bytes $drive.Free
    switch ($PSCmdlet.ParameterSetName) {
        'GB' {
            "Required: {0} GB | Available: {1} GB" -f ([float]$MinimumGB).ToString(), $freeSpace.GB | Trace-Output -Level:Verbose
            if ([float]$freeSpace.GB -gt [float]$MinimumGB) {
                return $true
            }

            # if we do not have enough disk space, we want to provide what was required vs what was available
            "Required: {0} GB | Available: {1} GB" -f ([float]$MinimumGB).ToString(), $freeSpace.GB | Trace-Output -Level:Error
            return $false
        }

        'MB' {
            "Required: {0} MB | Available: {1} MB" -f ([float]$MinimumMB).ToString(), $freeSpace.MB | Trace-Output -Level:Verbose
            if ([float]$freeSpace.MB -gt [float]$MinimumMB) {
                return $true
            }

            # if we do not have enough disk space, we want to provide what was required vs what was available
            "Required: {0} MB | Available: {1} MB" -f ([float]$MinimumMB).ToString(), $freeSpace.MB | Trace-Output -Level:Error
            return $false
        }
    }
}
