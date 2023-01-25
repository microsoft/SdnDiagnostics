# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Update-ServiceFabricCluster {
    <#
    .SYNOPSIS
        Upgrade the Service Fabric Cluster via Start-ServiceFabricClusterUpgrade and wait for the cluster to become healthy.
    .PARAMETER NcNodeList
        The list of Network Controller Nodes.
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
        [PSCustomObject[]]
        $NcNodeList,
        [Parameter(Mandatory = $true)]
        [String]
        $ManifestFolderNew,
        [Parameter(Mandatory = $true)]
        [hashtable]
        $CertRotateConfig,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    if ($NcNodeList.Count -eq 0) {
        throw New-Object System.NotSupportedException("NcNodeList is empty")
    }

    # Update the cluster manifest version to 1
    $clusterManifestXml = [xml](Get-Content "$ManifestFolderNew\ClusterManifest.current.xml")
    $currentVersionArray = $clusterManifestXml.ClusterManifest.Version.Split('.')
    $minorVersionIncrease = [int]$currentVersionArray[$currentVersionArray.Length - 1] + 1
    $currentVersionArray[$currentVersionArray.Length - 1] = $minorVersionIncrease
    $newVersionString = $currentVersionArray -Join '.'
    "Upgrade Service Fabric from $($clusterManifestXml.ClusterManifest.Version) to $newVersionString" | Trace-Output
    $clusterManifestXml.ClusterManifest.Version = $newVersionString
    $clusterManifestXml.Save("$ManifestFolderNew\ClusterManifest_new.xml")

    $currentNcNode = $null
    # Start Service Fabric Service for each NC
    foreach ($ncNode in $NcNodeList) {
        if(Test-ComputerNameIsLocal -ComputerName $ncNode.IpAddressOrFQDN){
            $currentNcNode = $ncNode
        }
    }
    $certThumb = $CertRotateConfig[$currentNcNode.NodeName.ToLower()]

    $clusterManifestPath = "$ManifestFolderNew\ClusterManifest_new.xml"

    if (!(Test-Path $clusterManifestPath)) {
        Throw "Path $clusterManifestPath not found"
    }

    "Upgrading Service Fabric Cluster with ClusterManifest at $clusterManifestPath" | Trace-Output

    # Sometimes access denied returned for the copy call, retry here to workaround this.
    $maxRetry = 3
    while($maxRetry -gt 0){
        try{
            if($CertRotateConfig["ClusterCredentialType"] -ieq "X509"){
                "Connecting to Service Fabric Cluster using cert with thumbprint: {0}" -f $certThumb | Trace-Output
                Connect-ServiceFabricCluster -X509Credential -FindType FindByThumbprint -FindValue $certThumb -ConnectionEndpoint "$($currentNcNode.IpAddressOrFQDN):49006" | Out-Null
            }
            else{
                Connect-ServiceFabricCluster | Out-Null
            }
            Copy-ServiceFabricClusterPackage -Config -ImageStoreConnectionString "fabric:ImageStore" -ClusterManifestPath  $clusterManifestPath -ClusterManifestPathInImageStore "ClusterManifest.xml"
            break
        }catch{
            "Copy-ServiceFabricClusterPackage failed with exception $_.Exception. Retry $(4 - $maxRetry)/3 after 60 seconds" | Trace-Output -Level:Warning
            Start-Sleep -Seconds 60
            $maxRetry --
        }
    }

    Register-ServiceFabricClusterPackage -Config -ClusterManifestPath "ClusterManifest.xml"
    Start-ServiceFabricClusterUpgrade -ClusterManifestVersion $NewVersionString -Config -UnmonitoredManual -UpgradeReplicaSetCheckTimeoutSec 30

    while ($true) {
        $upgradeStatus = Get-ServiceFabricClusterUpgrade
        "Current upgrade state: $($upgradeStatus.UpgradeState) UpgradeDomains: $($upgradeStatus.UpgradeDomains)" | Trace-Output
        if ($upgradeStatus.UpgradeState -eq "RollingForwardPending") {
            $nextNode = $upgradeStatus.NextUpgradeDomain
            "Next node to upgrade $nextNode" | Trace-Output
            try{
                Resume-ServiceFabricClusterUpgrade -UpgradeDomainName $nextNode
                # Catch exception for resume call, as sometimes, the upgrade status not updated intime caused duplicate resume call.
            }catch{
                "Exception in Resume-ServiceFabricClusterUpgrade $_.Exception" | Trace-Output -Level:Warning
            }
        }
        elseif ($upgradeStatus.UpgradeState -eq "Invalid" `
                -or $upgradeStatus.UpgradeState -eq "Failed") {
            Throw "Something wrong with the upgrade"
        }
        elseif ($upgradeStatus.UpgradeState -eq "RollingBackCompleted" `
                -or $upgradeStatus.UpgradeState -eq "RollingForwardCompleted") {
            "Upgrade has been completed" | Trace-Output
            break
        }
        else {
            "Waiting for current node upgrade to complete" | Trace-Output
        }

        Start-Sleep -Seconds 60
    }
}
