# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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

    try {
        $drive = Get-PSDrive $DriveLetter -ErrorAction Stop
        if ($null -eq $drive) {
            throw New-Object System.NullReferenceException("Unable to retrieve PSDrive information")
        }

        $freeSpace = Format-ByteSize -Bytes $drive.Free
        "Reporting {0}" -f $freeSpace | Trace-Output -Level:Verbose

        switch ($PSCmdlet.ParameterSetName) {
            'GB' {
                if ([float]$freeSpace.GB -gt [float]$MinimumGB) {
                    return $true
                }
            }

            'MB' {
                if ([float]$freeSpace.MB -gt [float]$MinimumMB) {
                    return $true
                }
            }
        }

        return $false
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
