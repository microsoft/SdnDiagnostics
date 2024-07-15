function Get-NetworkControllerConfigState {
    <#
    .SYNOPSIS
        Outputs a set of configuration state files for the network controller role.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .EXAMPLE
        PS> Get-NetworkControllerConfigState -OutputDirectory "C:\Temp\CSS_SDN"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    $currentErrorActionPreference = $ErrorActionPreference
    $ProgressPreference = 'SilentlyContinue'
    $ErrorActionPreference = 'SilentlyContinue'

    try {
        $config = Get-SdnModuleConfiguration -Role 'NetworkController'
        [string]$outDir = Join-Path -Path $OutputDirectory.FullName -ChildPath "ConfigState"
        [string]$regDir = Join-Path -Path $OutputDirectory.FullName -ChildPath "Registry"
        [string]$ncAppDir = Join-Path $OutputDirectory.FullName -ChildPath "NCApp"

        if (-NOT (Initialize-DataCollection -Role $config.Name -FilePath $outDir -MinimumMB 100)) {
            "Unable to initialize environment for data collection" | Trace-Output -Level:Error
            return
        }

        "Collect configuration state details for role {0}" -f $config.Name | Trace-Output

        Export-RegistryKeyConfigDetails -Path $config.properties.regKeyPaths -OutputDirectory $regDir
        Get-CommonConfigState -OutputDirectory $outDir

        # enumerate dll binary version for NC application
        $ncAppDirectories = Get-ChildItem -Path "$env:SystemRoot\NetworkController" -Directory
        foreach($directory in $ncAppDirectories){
            [string]$fileName = "FileInfo_{0}" -f $directory.BaseName
            Get-Item -Path "$($directory.FullName)\*" -Include *.dll,*.exe | Export-ObjectToFile -FilePath $ncAppDir -Name $fileName -FileType txt -Format List
        }

        switch ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType) {
            'ServiceFabric' {
                Get-NetworkControllerSFConfigState @PSBoundParameters
            }
            'FailoverCluster' {
                Get-NetworkControllerFCConfigState @PSBoundParameters
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }

    $ProgressPreference = 'Continue'
    $ErrorActionPreference = $currentErrorActionPreference
}
