# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Initialize-DataCollection {
    <##>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'GB')]
        [Parameter(Mandatory = $false, ParameterSetName = 'MB')]
        [SdnRoles]$Role,

        [Parameter(Mandatory = $true, ParameterSetName = 'GB')]
        [Parameter(Mandatory = $true, ParameterSetName = 'MB')]
        [System.String[]]$FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'GB')]
        [System.Int32]$MinimumGB,

        [Parameter(Mandatory = $true, ParameterSetName = 'MB')]
        [System.Int32]$MinimumMB
    )

    # ensure that the appropriate windows feature is installed and ensure module is imported
    if ($Role) {
        $config = Get-SdnRoleConfiguration -Role $Role
        $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
        if (!$confirmFeatures) {
            throw New-Object System.NotSupportedException("Required feature is missing")
        }

        $confirmModules = Confirm-RequiredModulesLoaded -Name $config.requiredModules
        if (!$confirmModules) {
            throw New-Object System.NotSupportedException("Required module is not loaded")
        }
    }

    # create the directories if does not already exist
    foreach ($path in $FilePath) {
        if (!(Test-Path -Path $path -PathType Container)) {
            $null = New-Item -Path $path -ItemType Directory -Force
        }
        else {
            "{0} already exists. Performing cleanup operation" -f $path | Trace-Output -Level:Warning
            Remove-Item -Path $path\* -Recurse -Force
        }

        # confirm sufficient disk space
        [System.Char]$driveLetter = (Split-Path -Path $path -Qualifier).Replace(':','')

        switch ($PSCmdlet.ParameterSetName) {
            'GB' {
                $diskSpace = Confirm-DiskSpace -DriveLetter $driveLetter -MinimumGB $MinimumGB
            }
            'MB' {
                $diskSpace = Confirm-DiskSpace -DriveLetter $driveLetter -MinimumMB $MinimumMB
            }
        }

        if (!($diskSpace)) {
            throw New-Object System.Exception("Insufficient disk space detected")
        }
    }

    return $true
}
