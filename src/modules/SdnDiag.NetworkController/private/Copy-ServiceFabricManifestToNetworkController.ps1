function Copy-ServiceFabricManifestToNetworkController {
    <#
    .SYNOPSIS
        Copy the Service Fabric Manifest Files to Network Controller.
    .PARAMETER NcNodeList
        The NcNodeList that retrieved via Get-SdnNetworkControllerInfoOffline.
    .PARAMETER ManifestFolder
        The Manifest Folder path for Manifest files copy from.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $NcNodeList,
        [Parameter(Mandatory = $true)]
        [String]
        $ManifestFolder,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if ($NcNodeList.Count -eq 0) {
            Trace-Output "No NC VMs found" -Level:Error
            return
        }
        Trace-Output "Copying Service Fabric Manifests to NC VMs: $($NcNodeList.IpAddressOrFQDN)"

        Trace-Output "Stopping Service Fabric Service"
        foreach ($nc in $NcNodeList.IpAddressOrFQDN) {
            Invoke-PSRemoteCommand -ComputerName $nc -ScriptBlock {
                Write-Host "[$(HostName)] Stopping Service Fabric Service"
                Stop-Service FabricHostSvc -Force
            } -Credential $Credential
        }


        $NcNodeList | ForEach-Object {
            $fabricFolder = "c:\programdata\Microsoft\Service Fabric\$($_.NodeName)\Fabric"

            $version = Invoke-PSRemoteCommand -ComputerName $_.IpAddressOrFQDN -ScriptBlock {
                $fabricPkgFile = "$using:fabricFolder\Fabric.Package.current.xml"
                $xml = [xml](get-content $fabricPkgFile)
                $version = $xml.ServicePackage.DigestedConfigPackage.ConfigPackage.Version
                return $version
            } -Credential $Credential

            $fabricConfigDir = Join-Path -Path $fabricFolder -ChildPath $("Fabric.Config." + $version)
            $settingsFile = Join-Path -Path $fabricConfigDir -ChildPath "Settings.xml"

            Invoke-PSRemoteCommand -ComputerName $_.IpAddressOrFQDN -ScriptBlock {
                Set-ItemProperty -Path "$using:fabricFolder\ClusterManifest.current.xml" -Name IsReadOnly -Value $false | Out-Null
                Set-ItemProperty -Path "$using:fabricFolder\Fabric.Data\InfrastructureManifest.xml" -Name IsReadOnly -Value $false | Out-Null
                Set-ItemProperty -Path $using:settingsFile -Name IsReadOnly -Value $false | Out-Null

            } -Credential $Credential

            Copy-FileToRemoteComputer -Path "$ManifestFolder\ClusterManifest.current.xml" -Destination "$fabricFolder\ClusterManifest.current.xml" -ComputerName $_.IpAddressOrFQDN -Credential $Credential
            Copy-FileToRemoteComputer -Path "$ManifestFolder\InfrastructureManifest.xml" -Destination "$fabricFolder\Fabric.Data\InfrastructureManifest.xml" -ComputerName $_.IpAddressOrFQDN -Credential $Credential
            Copy-FileToRemoteComputer -Path "$ManifestFolder\$($_.IpAddressOrFQDN)\settings.xml" -Destination $settingsFile -ComputerName $_.IpAddressOrFQDN -Credential $Credential
        }
    }
    catch {
        $_ | Trace-Exception
    }
}
