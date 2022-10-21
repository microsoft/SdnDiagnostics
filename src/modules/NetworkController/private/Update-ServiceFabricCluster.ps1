# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Update-ServiceFabricCluster {
    <#
    .SYNOPSIS
        Upgrade the Service Fabric Cluster via Start-ServiceFabricClusterUpgrade and wait for the cluster to become healthy.
    .PARAMETER NcVMs
        The list of Network Controller VMs.
	.PARAMETER ClusterCredentialType
		X509, Windows or None.
	.PARAMETER ManifestFolderNew
		The New Manifest Folder contains the new Manifest Files.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String[]]
        $NcVms,
        [Parameter(Mandatory = $true)]
        [String]
        $ManifestFolderNew,
        [String]
        $ClusterCredentialType = "X509",
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if ($NcVMs.Count -eq 0) {
            Trace-Output "No NC VMs found" -Level:Error
            return
        }
    
        # Update the cluster manifest version to 1
        $clusterManifestXml = [xml](Get-Content "$ManifestFolderNew\ClusterManifest.current.xml")
        $currentVersionArray = $clusterManifestXml.ClusterManifest.Version.Split('.')
        $minorVersionIncrease = [int]$currentVersionArray[$currentVersionArray.Length - 1] + 1
        $currentVersionArray[$currentVersionArray.Length - 1] = $minorVersionIncrease
        $newVersionString = $currentVersionArray -Join '.'
        Write-Host "Upgrade Service Fabric from $($clusterManifestXml.ClusterManifest.Version) to $newVersionString"
        $clusterManifestXml.ClusterManifest.Version = $newVersionString
        $clusterManifestXml.Save("$ManifestFolderNew\ClusterManifest_new.xml")
    
        Copy-Item "$ManifestFolderNew\ClusterManifest_new.xml" "\\$($NcVms[0])\c$\ClusterManifest_new.xml" -Verbose
        
        # Register the new Cluster Manifest to ImageStore
        $sfUpgradeScript = {   
            param(
                [String]
                $ClusterCredentialType,
                [String]
                $NewVersionString
            ) 
            $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName + "." + (get-ciminstance win32_computersystem).Domain
            $cert = (Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -match $NodeFQDN }) | Sort-Object -Property NotBefore -Descending | Select-Object -First 1    
            $certThumb = $cert.Thumbprint
    
            if($ClusterCredentialType -eq "X509")
            {
                Connect-ServiceFabricCluster -X509Credential -FindType FindByThumbprint -FindValue $certThumb -ConnectionEndpoint "$($NodeFQDN):49006" | Out-Null
            }else
            {
                Connect-ServiceFabricCluster | Out-Null
            }
            $clusterManifestPath = "C:\ClusterManifest_new.xml"
        
            if (!(Test-Path $clusterManifestPath)) {
                Throw "Path $clusterManifestPath not foound" 
            }
            Copy-ServiceFabricClusterPackage -Config -ImageStoreConnectionString "fabric:ImageStore" -ClusterManifestPath  $clusterManifestPath -ClusterManifestPathInImageStore "ClusterManifest.xml"
            Register-ServiceFabricClusterPackage -Config -ClusterManifestPath "ClusterManifest.xml"
            Start-ServiceFabricClusterUpgrade -ClusterManifestVersion $NewVersionString -Config -UnmonitoredManual -UpgradeReplicaSetCheckTimeoutSec 30
    
            while ($true) {
                $upgradeStatus = Get-ServiceFabricClusterUpgrade
                Write-Host "Current upgrade state: $($upgradeStatus.UpgradeState) UpgradeDomains: $($upgradeStatus.UpgradeDomains)"
                if ($upgradeStatus.UpgradeState -eq "RollingForwardPending") {
                    $nextNode = $upgradeStatus.NextUpgradeDomain
                    Write-Host "Next node to upgrade $nextNode"
                    Resume-ServiceFabricClusterUpgrade -UpgradeDomainName $nextNode
                }
                elseif ($upgradeStatus.UpgradeState -eq "Invalid" `
                        -or $upgradeStatus.UpgradeState -eq "Failed") {
                    Throw "Something wrong with the upgrade"
                }
                elseif ($upgradeStatus.UpgradeState -eq "RollingBackCompleted" `
                        -or $upgradeStatus.UpgradeState -eq "RollingForwardCompleted") {
                    Write-Host "Upgrade has been completed"
                    break
                }
                else {
                    Write-Host "Waiting for current node upgrade to complete"
                }
    
                Start-Sleep -Seconds 60
            }
        }
    
        $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName + "." + (get-ciminstance win32_computersystem).Domain
        if($NcVMs -contains $NodeFQDN){
            Invoke-Command -ScriptBlock $sfUpgradeScript -ArgumentList $ClusterCredentialType,$newVersionString
        }
        else {
            Invoke-Command -ComputerName $NcVMs[0] -ScriptBlock $sfUpgradeScript -ArgumentList $ClusterCredentialType,$newVersionString -Credential $Credential
        }
        
        Trace-Output "Ensure Service Fabric Healthy"
        Wait-ServiceFabricClusterHealthy -NcVMs $NcVms -ClusterCredentialType $ClusterCredentialType -Credential $Credential
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}