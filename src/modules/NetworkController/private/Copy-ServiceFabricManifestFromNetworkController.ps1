# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Copy-ServiceFabricManifestFromNetworkController {
    <#
    .SYNOPSIS
        Copy the Service Fabric Manifest Files from Network Controller.
    .PARAMETER NcNodeList
        The NcNodeList that retrieved via Get-SdnNetworkControllerInfoOffline.
    .PARAMETER ManifestFolder
        The Manifest Folder path for Manifest files copy to.
    .PARAMETER ManifestFolderNew
        The New Manifest Folder path for updated Manifest files.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $NcNodeList,
        [Parameter(Mandatory = $true)]
        [String]
        $ManifestFolder,
        [Parameter(Mandatory = $true)]
        [String]
        $ManifestFolderNew,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if ($NcNodeList.Count -eq 0) {
            Trace-Output "No NC Node found" -Level:Error
            return
        }
        Trace-Output "Copying Manifest files from $($NcNodeList.IpAddressOrFQDN)" -Level:Verbose
    
        New-Item -Path $ManifestFolder -type Directory -Force | Out-Null
        New-Item $ManifestFolderNew -ItemType Directory -Force | Out-Null

        $fabricFolder = "c:\programdata\Microsoft\Service Fabric\$($NcNodeList[0].NodeName)\Fabric"
        Copy-FileFromRemoteComputer -Path "$fabricFolder\ClusterManifest.current.xml" -ComputerName $($NcNodeList[0].IpAddressOrFQDN) -Destination $ManifestFolder -Credential $Credential
        Copy-FileFromRemoteComputer -Path "$fabricFolder\Fabric.Data\InfrastructureManifest.xml" -ComputerName $($NcNodeList[0].IpAddressOrFQDN) -Destination $ManifestFolder -Credential $Credential
        
        $NcNodeList | ForEach-Object {
            $fabricFolder = "c:\programdata\Microsoft\Service Fabric\$($_.NodeName)\Fabric"
            
            $version = Invoke-Command -ComputerName $_.IpAddressOrFQDN -ScriptBlock {
                param(
                    [String]$NodeName
                )
                $fabricFolder = "c:\programdata\Microsoft\Service Fabric\$NodeName\Fabric"
                $fabricPkgFile = "$fabricFolder\Fabric.Package.current.xml"
                $xml = [xml](get-content $fabricPkgFile)
                $version = $xml.ServicePackage.DigestedConfigPackage.ConfigPackage.Version
                return $version
            } -Credential $Credential -ArgumentList $_.NodeName
            
            $fabricConfigDir = Join-Path -Path $fabricFolder -ChildPath $("Fabric.Config." + $version)
            $settingsFile = Join-Path -Path $fabricConfigDir -ChildPath "Settings.xml"
            New-Item -Path "$ManifestFolder\$($_.IpAddressOrFQDN)" -type Directory -Force | Out-Null
            New-Item -Path "$ManifestFolderNew\$($_.IpAddressOrFQDN)" -type Directory -Force | Out-Null

            Copy-FileFromRemoteComputer -Path $settingsFile -ComputerName $_.IpAddressOrFQDN -Destination "$ManifestFolder\$($_.IpAddressOrFQDN)" -Credential $Credential
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
