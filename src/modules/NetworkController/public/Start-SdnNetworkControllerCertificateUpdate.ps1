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

	.PARAMETER CertRotateConfig
		The Config generated by New-SdnCertificateRotationConfig to include NC REST certificate thumbprint and node certificate thumbprint.      
    .EXAMPLE
        Start-NetworkControllerCertificateUpdate -NetworkController nc01
    #>
    
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]
        $CertRotateConfig,
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    # ensure that the module is running as local administrator
    $elevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-NOT $elevated) {
        throw New-Object System.Exception("This function requires elevated permissions. Run PowerShell as an Administrator and import the module again.")
    }

    $config = Get-SdnRoleConfiguration -Role 'NetworkController'
    $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
    if (-NOT ($confirmFeatures)) {
        throw New-Object System.NotSupportedException("The current machine is not a NetworkController, run this on NetworkController.")
    }

    $NcUpdateFolder = "$(Get-WorkingDirectory)\NcCertUpdate_{0}" -f (Get-FormattedDateTimeUTC)
    $ManifestFolder = "$NcUpdateFolder\manifest"
    $ManifestFolderNew = "$NcUpdateFolder\manifest_new"
    
    $result = Test-NetworkControllerRemoteAccess -Credential $Credential

    if ($result -eq $false) {
        Write-Verbose "Network Controller Remote Access test failed. PowerShell Remote Access or Admin Share access failed."
        return
    }

    $NcInfraInfo = Get-SdnNetworkControllerInfoOffline -Credential $Credential
    Trace-Output "Network Controller Infrastrucutre Info detected:"
    Trace-Output "ClusterCredentialType: $($NcInfraInfo.ClusterCredentialType)"
    Trace-Output "NcRestName: $($NcInfraInfo.NcRestName)"
    
    $NcNodeList = $NcInfraInfo.NodeList

    if ($null -eq $NcNodeList -or $NcNodeList.Count -eq 0) {
        Trace-Output "Failed to get NC Node List from NetworkController: $(HostName)" -Level:Error
    }

    Trace-Output "NcNodeList: $($NcNodeList.IpAddressOrFQDN)"

    Trace-Output "Validate CertRotateConfig"
    if(!(Test-SdnCertificateRotationConfig -NcNodeList $NcNodeList -CertRotateConfig $CertRotateConfig -Credential $Credential)){
        Trace-Output "Invalid CertRotateConfig, please correct the configuration and try again" -Level:Error
        return 
    }

    if ([String]::IsNullOrEmpty($NcInfraInfo.NcRestName)) {
        Trace-Output "Failed to get NcRestName using current secret certificate thumbprint. This might indicate the certificate not found on $(HOSTNAME). We won't be able to recover." -Level:Error
        throw New-Object System.NotSupportedException("Current NC Rest Cert not found, Certificate Rotation cannot be continue.")
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
    
    $NcRestCertThumbprint = $CertRotateConfig["NcRestCert"]
    Trace-Output "Step 1 Copy manifests and settings.xml"
    Copy-ServiceFabricManifestFromNetworkController -NcNodeList $NcNodeList -ManifestFolder $ManifestFolder -ManifestFolderNew $ManifestFolderNew -Credential $Credential
    
    # Step 2 Update certificate thumbprint
    Trace-Output "Step 2 Update certificate thumbprint"
    Update-NetworkControllerCertificateInManifest -NcNodeList $NcNodeList -ManifestFolder $ManifestFolder -ManifestFolderNew $ManifestFolderNew -CertRotateConfig $CertRotateConfig -Credential $Credential
    
    # Step 3 Generate New Secrets
    Trace-Output "Step 3 Generate New Secrets"
    $SecretUpdated = New-NetworkControllerClusterSecret -NcVMs $NcVms -ManifestFolder $ManifestFolder -ManifestFolderNew $ManifestFolderNew -NcRestCertThumbprint $NcRestCertThumbprint -Credential $Credential
    if (!$SecretUpdated) {
        # If secret failed to be generated or updated. We stop here to not modify cluster manifest.
        Trace-Output "Failed to get new secret." -Level:Error
        return
    }

    # Step 4 Copy the new files back to the NC vms
    Trace-Output "Step 4 Copy the new files back to the NC vms"
    Copy-ServiceFabricManifestToNetworkController -NcNodeList $NcNodeList -ManifestFolder $ManifestFolderNew -Credential $Credential
    
    # Step 5 Start FabricHostSvc and wait for SF system service to become healty
    Trace-Output "Step 5 Start FabricHostSvc and wait for SF system service to become healty"
    Trace-Output "Step 5.1 Update Network Controller Certificate ACL to allow 'Network Service' Access"
    Update-NetworkControllerCertificateAcl -NcNodeList $NcNodeList -CertRotateConfig $CertRotateConfig -Credential $Credential
    Trace-Output "Step 5.2 Start Service Fabric Host Service and wait"
    $clusterHealthy = Wait-ServiceFabricClusterHealthy -NcVMs $NcVMs -ClusterCredentialType $NcInfraInfo.ClusterCredentialType -Credential $Credential
    Trace-Output "ClusterHealthy: $clusterHealthy"
    if($clusterHealthy -ne $true){
        throw New-Object System.NotSupportedException("Cluster unheathy after manifest update, we cannot continue with current situation")
    }
    # Step 6 Invoke SF Cluster Upgrade 
    Trace-Output "Step 6 Invoke SF Cluster Upgrade"
    Update-ServiceFabricCluster -NcVms $NcVMs -ManifestFolderNew $ManifestFolderNew -ClusterCredentialType $NcInfraInfo.ClusterCredentialType -Credential $Credential
    
    # Step 7 Fix NC App
    Trace-Output "Step 7 Fix NC App"
    Trace-Output "Step 7.1 Updating Network Controller Global and Cluster Config"
    if ($NcInfraInfo.ClusterCredentialType -eq "X509") {
        Update-NetworkControllerConfig -NcNodeList $NcNodeList -CertRotateConfig $CertRotateConfig -Credential $Credential
    }
    
    Trace-Output "Step 7.2 Rotate Network Controller Certificate"
    $null = Invoke-CertRotateCommand -Command 'Set-NetworkController' -Credential $Credential -Thumbprint $NcRestCertThumbprint

    # Step 8 Update REST CERT credential
    Trace-Output "Step 8 Update REST CERT credential"
    # Step 8.1 Wait for NC App Healthy
    Trace-Output "Step 8.1 Wiating for Network Controller App Ready"
    Wait-NetworkControllerAppHealthy -Interval 60
    Trace-Output "Step 8.2 Updating REST CERT Credential object calling REST API"
    Update-NetworkControllerCredentialResource -NcUri "https://$($NcInfraInfo.NcRestName)" -NewRestCertThumbprint $NcRestCertThumbprint -Credential $NcRestCredential
}