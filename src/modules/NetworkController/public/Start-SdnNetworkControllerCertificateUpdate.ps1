# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Start-SdnNetworkControllerCertificateUpdate {
    <#
    .SYNOPSIS
        Start the Network Controller Certificate Update.
    .DESCRIPTION
        Start the Network Controller Certificate Update.
        This will use the latest issued certificate on each of the NC VMs to replace existing certificates. Ensure below before execute this command:
        - NC Rest Certificate and NC Node certificate created on each NC and trusted. 
        - "Network Service" account have read access to the private file of the new certificates. 
        - NC Rest Certificate need to be trusted by all SLB MUX VMs and SDN Hosts.

        For Self-Signed Certificate. This can also be created by 'New-NetworkControllerCertificate'. To get more details, run 'Get-Help New-NetworkControllerCertificate'

        About SDN Certificate Requirement:
        https://docs.microsoft.com/en-us/windows-server/networking/sdn/security/sdn-manage-certs

    .PARAMETER NetworkController
        Specifies one of the Network Controller VM name.

    .PARAMETER NcRestName
        Specifies NC Cluster Rest Name in FQDN.
    
    .PARAMETER NcUpdateFolder
        Specifies Nc Update Folder path used to store old manifest file from Network Controller Cluster and new manifest file generated.
        Default to "C:\NcCertUpdate" 

    .EXAMPLE
        Start-NetworkControllerCertificateUpdate -NetworkController nc01
    #>
    
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $NetworkController = $(HostName),
        [Parameter(Mandatory = $false)]
        [String]
        $NcRestName = "",
        [String]
        $NcUpdateFolder = "C:\NcCertUpdate",
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,
        [switch]
        $NoClusterUpgrade
    )

    try {
        $ManifestFolder = "$NcUpdateFolder\manifest"
        $ManifestFolderNew = "$NcUpdateFolder\manifest_new"
        
        $result = Test-NetworkControllerRemoteAccess -NetworkController $NetworkController
    
        if ($result -eq $false) {
            Write-Verbose "Network Controller Remote Access test failed. PowerShell Remote Access or Admin Share access failed."
            return
        }
    
        $NcInfraInfo = Get-SdnNetworkControllerInfoOffline -NetworkController $NetworkController -Credential $Credential
        Trace-Output "Network Controller Infrastrucutre Info detected:"
        Trace-Output "ClusterCredentialType: $($NcInfraInfo.ClusterCredentialType)"
        Trace-Output "NcRestName: $($NcInfraInfo.NcRestName)"
        
        $NcNodeList = $NcInfraInfo.NodeList
    
        if ($null -eq $NcNodeList -or $NcNodeList.Count -eq 0) {
            Trace-Output "Failed to get NC Node List from NetworkController: $NetworkController" -Level:Error
        }
    
        Trace-Output "NcNodeList: $($NcNodeList.IpAddressOrFQDN)"
    
        if ([String]::IsNullOrEmpty($NcInfraInfo.NcRestName)) {
            Trace-Output "Failed to get NcRestName using current secret certificate thumbprint. This might indicate the certificate not found on $NetworkController. We won't be able to recover." -Level:Error
            if ([String]::IsNullOrEmpty($NcRestName)) {
                # If user not specified NcRestName as well. Exit
                return
            }
            else {
                Trace-Output "Use provided NcRestName $NcRestName"
            }
        }
        else {
            if ([String]::IsNullOrEmpty($NcRestName)) {
                $NcRestName = $NcInfraInfo.NcRestName
            }
            else {
                if ($NcRestName -ne $NcInfraInfo.NcRestName) {
                    Trace-Output "Provided NcRestName [$NcRestName] does not match detected NcRestName [$($NcInfraInfo.NcRestName)]." -Level:Error
                    return
                }
            }
        }
    
        $NcVms = $NcNodeList.IpAddressOrFQDN
    
        if (Test-Path $NcUpdateFolder) {
            $items = Get-ChildItem $NcUpdateFolder
            if ($items.Count -gt 0) {
                $confirmCleanup = Read-Host "The Folder $NcUpdateFolder not empty. Need to be cleared. Enter Y to confirm"
                if ($confirmCleanup -eq "Y") {
                    $items | Remove-Item -Force -Recurse
                }
                else {
                    return
                }
            }
        }
    
        foreach ($nc in $NcVms) {
            Invoke-Command -ComputerName $nc -ScriptBlock {
                Write-Host "[$(HostName)] Stopping Service Fabric Service"
                Stop-Service FabricHostSvc -Force
            }
        }
        
        Trace-Output "Step 1 Copy manifests and settings.xml"
        Copy-ServiceFabricManifestFromNetworkController -NcNodeList $NcNodeList -ManifestFolder $ManifestFolder -ManifestFolderNew $ManifestFolderNew -Credential $Credential
        
        # Step 2 Update certificate thumbprint
        Trace-Output "Step 2 Update certificate thumbprint"
        Update-NetworkControllerCertificateInManifest -NcVMs $NcVMs -NcRestName $NcRestName -ManifestFolder $ManifestFolder -ManifestFolderNew $ManifestFolderNew -Credential $Credential
        
        # Step 3 Generate New Secrets
        Trace-Output "Step 3 Generate New Secrets"
        $SecretUpdated = New-NetworkControllerClusterSecret -NcVMs $NcVms -NcRestName $NcRestName -ManifestFolder $ManifestFolder -ManifestFolderNew $ManifestFolderNew -Credential $Credential
        if (!$SecretUpdated) {
            # If secret failed to be generated or updated. We stop here to not modify cluster manifest.
            Trace-Output "Failed to get new secret." -Level:Error
            return
        }
    
        # Step 4 Copy the new files back to the NC vms
        Trace-Output "Step 4 Copy the new files back to the NC vms"
        Copy-ServiceFabricManifestToNetworkController -NcNodeList $NcNodeList -ManifestFolder $ManifestFolder -ManifestFolderNew $ManifestFolderNew -Credential $Credential
        
        # Step 5 Start FabricHostSvc and wait for SF system service to become healty
        Trace-Output "Step 5 Start FabricHostSvc and wait for SF system service to become healty"
        Trace-Output "Step 5.1 Update Network Controller Certificate ACL to allow 'Network Service' Access"
        Update-NetworkControllerCertificateAcl -NcVMs $NcVMs -NcRestName $NcRestName -ClusterCredentialType $NcInfraInfo.ClusterCredentialType -Credential $Credential
        Trace-Output "Step 5.2 Start Service Fabric Host Service and wait"
        Wait-ServiceFabricClusterHealthy -NcVMs $NcVMs -ClusterCredentialType $NcInfraInfo.ClusterCredentialType -Credential $Credential
        
        # Step 6 Invoke SF Cluster Upgrade 
        Trace-Output "Step 6 Invoke SF Cluster Upgrade"
        if ($NoClusterUpgrade) {
            Trace-Output "Cluster Upgrade Skipped"
        }
        else {
            Update-ServiceFabricCluster -NcVms $NcVMs -ManifestFolderNew $ManifestFolderNew -ClusterCredentialType $NcInfraInfo.ClusterCredentialType -Credential $Credential
        }
        
        # Step 7 Fix NC App
        Trace-Output "Step 7 Fix NC App"
        Trace-Output "Step 7.1 Updating Network Controller Global Config"
        Update-NetworkControllerGlobalConfig -NcNodeList $NcNodeList -NcRestName $NcRestName -Credential $Credential
    
        if ($NcInfraInfo.ClusterCredentialType -eq "X509") {
            Trace-Output "Step 7.1 Updating Network Controller Cluster Config"
            Update-NetworkControllerClusterConfig -NcVMs $NcVMs -Credential $Credential
        }
        
        Trace-Output "Step 7.2 Rotate Network Controller Certificate"
        $ncRestCert = Get-NetworkControllerCertificate -NetworkController $NcVMs[0] -NcRestName $NcRestName
        $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName + "." + (get-ciminstance win32_computersystem).Domain
        if ($NcVMs -contains $NodeFQDN) {
            Trace-Output "Currently running on one of the NC VM [$(HOSTNAME)], Run Set-NetworkController to update certificate"
            $ncRestCertObj = Get-Item Cert:\LocalMachine\My\$ncRestCert 
            Set-NetworkController -ServerCertificate $ncRestCertObj -Verbose
        }
        else {
            Trace-Output "[ACTION REQUIRED] Login to one of the NC VM and run below command to update certificate:" -Level:Warning
            Trace-Output "Set-NetworkController -ServerCertificate (Get-Item Cert:\LocalMachine\My\$ncRestCert) -Verbose" -Level:Warning
            Trace-Output "When finished, press any key to continue" -Level:Warning
            [void][System.Console]::ReadKey($true)
        }
        # Step 8 Update REST CERT credential
        Trace-Output "Step 8 Update REST CERT credential"
        # Step 8.1 Wait for NC App Healthy
        Trace-Output "Step 8.1 Wiating for Network Controller App Ready"
        if ($NcVMs -contains $NodeFQDN) {
            Wait-NetworkControllerAppHealthy -Interval 60
        }
        else {
            Wait-NetworkControllerAppHealthy -NetworkController $NcVMs[0] -Interval 60
        }
        Trace-Output "Step 8.2 Updating REST CERT Credential object calling REST API"
        Update-NetworkControllerCredentialResource -NcUri "https://$NcRestName" -NewRestCertThumbprint $ncRestCert -Credential $NcRestCredential
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
