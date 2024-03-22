function Confirm-DiskSpace {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'GB')]
        [Parameter(Mandatory = $false, ParameterSetName = 'MB')]
        [System.Char]$DriveLetter,

        [Parameter(Mandatory = $true, ParameterSetName = 'GB')]
        $MinimumGB,

        [Parameter(Mandatory = $true, ParameterSetName = 'MB')]
        $MinimumMB
    )

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
