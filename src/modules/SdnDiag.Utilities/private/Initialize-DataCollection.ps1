function Initialize-DataCollection {
    <#
    .SYNOPSIS
        Prepares the environment for data collection that logs will be saved to.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'GB')]
        [Parameter(Mandatory = $false, ParameterSetName = 'MB')]
        [String]$Role,

        [Parameter(Mandatory = $true, ParameterSetName = 'GB')]
        [Parameter(Mandatory = $true, ParameterSetName = 'MB')]
        [System.IO.FileInfo]$FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'GB')]
        [System.Int32]$MinimumGB,

        [Parameter(Mandatory = $true, ParameterSetName = 'MB')]
        [System.Int32]$MinimumMB
    )

    # ensure that the appropriate windows feature is installed and ensure module is imported
    if ($Role) {
        $config = Get-SdnModuleConfiguration -Role $Role
        $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
        if (-NOT ($confirmFeatures)) {
            "Required feature is missing: {0}" -f ($config.windowsFeature -join ', ') | Trace-Output -Level:Failure
            return $false
        }

        $confirmModules = Confirm-RequiredModulesLoaded -Name $config.requiredModules
        if (-NOT ($confirmModules)) {
            "Required module is not loaded: {0}" -f ($config.requiredModules -join ', ')| Trace-Output -Level:Failure
            return $false
        }
    }

    # create the directories if does not already exist
    if (-NOT (Test-Path -Path $FilePath.FullName -PathType Container)) {
        "Creating {0}" -f $FilePath.FullName | Trace-Output -Level:Verbose
        $null = New-Item -Path $FilePath.FullName -ItemType Directory -Force
    }

    # confirm sufficient disk space
    [System.Char]$driveLetter = (Split-Path -Path $FilePath.FullName -Qualifier).Replace(':','')
    switch ($PSCmdlet.ParameterSetName) {
        'GB' {
            $diskSpace = Confirm-DiskSpace -DriveLetter $driveLetter -MinimumGB $MinimumGB
        }
        'MB' {
            $diskSpace = Confirm-DiskSpace -DriveLetter $driveLetter -MinimumMB $MinimumMB
        }
    }

    if (-NOT ($diskSpace)) {
        "Insufficient disk space detected." | Trace-Output -Level:Failure
        return $false
    }

    return $true
}
