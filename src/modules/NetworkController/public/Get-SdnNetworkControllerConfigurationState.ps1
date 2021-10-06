# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnNetworkControllerConfigurationState {
    <#
    .SYNOPSIS
        Outputs a set of configuration state files for the network controller role.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .EXAMPLE
        PS> Get-SdnNetworkControllerConfigurationState -OutputDirectory "C:\Temp\CSS_SDN"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    $ProgressPreference = 'SilentlyContinue'

    try {
        $config = Get-SdnRoleConfiguration -Role:NetworkController

        # ensure that the appropriate windows feature is installed and ensure module is imported
        $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
        if(!$confirmFeatures){
            throw New-Object System.Exception("Required feature is missing")
        }

        $confirmModules = Confirm-RequiredModulesLoaded -Name $config.requiredModules
        if(!$confirmModules){
            throw New-Object System.Exception("Required module is not loaded")
        }

        # create the OutputDirectory if does not already exist
        if(!(Test-Path -Path $OutputDirectory.FullName -PathType Container)){
            $null = New-Item -Path $OutputDirectory.FullName -ItemType Directory -Force
        }

        # confirm sufficient disk space
        [System.Char]$driveLetter = (Split-Path -Path $OutputDirectory.FullName -Qualifier).Replace(':','')
        if (-NOT (Confirm-DiskSpace -DriveLetter $driveLetter -MinimumMB 100)) {
            throw New-Object System.Exception("Insufficient disk space detected")
        }

        # dump out the regkey properties
        Export-RegistryKeyConfigDetails -Path $config.properties.regKeyPaths -OutputDirectory (Join-Path -Path $OutputDirectory.FullName -ChildPath "Registry")

        # enumerate dll binary version for NC application
        $ncAppDirectories = Get-ChildItem -Path "C:\Windows\NetworkController" -Directory
        $outputDir = New-Item -Path (Join-Path -Path $OutputDirectory.FullName -ChildPath "NCApplication") -ItemType Directory -Force
        foreach($directory in $ncAppDirectories){
            [System.String]$fileName = "FileInfo_{0}" -f $directory.BaseName
            Get-Item -Path "$($directory.FullName)\*" -Include *.dll,*.exe | Export-ObjectToFile -FilePath $outputDir.FullName -Name $fileName -FileType txt -Format List
        }

        Get-GeneralConfigurationState -OutputDirectory $OutputDirectory.FullName
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }

    $ProgressPreference = 'Continue'
}
