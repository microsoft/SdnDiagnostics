# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Update-NetworkControllerCertificateInManifest {
    <#
    .SYNOPSIS
        Update Network Controller Manifest File with new Network Controller Certificate.
    .PARAMETER NcVMs
        The list of Network Controller VMs.
	.PARAMETER NcRestName
		The Network Controller REST Name in FQDN format used to find the REST Certificate to be used.
	.PARAMETER ManifestFolder
		The Manifest Folder contains the orginal Manifest Files.
	.PARAMETER ManifestFolderNew
		The New Manifest Folder contains the new Manifest Files. Updated manifest file save here.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String[]]
        $NcVMs,
        [Parameter(Mandatory = $true)]
        [String]
        $NcRestName,
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
        if ($NcVMs.Count -eq 0) {
            Trace-Output "No NC VMs found" -Level:Error
            return
        }
    
        # Prepare the cert thumbprint to be used
        # Update certificates ClusterManifest.current.xml
        
        $clusterManifestXml = [xml](Get-Content "$ManifestFolder\ClusterManifest.current.xml")
    
        if ($null -eq $clusterManifestXml) {
            Trace-Output "ClusterManifest not found at $ManifestFolder\ClusterManifest.current.xml" -Level:Error
            throw 
        }
    
        # Update SecretsCertificate to new REST Cert
        $NcRestCertThumbprint = Get-NetworkControllerCertificate -NetworkController $NcVMs[0] -NcRestName $NcRestName
    
        Trace-Output "Updating SecretsCertificate with new rest cert thumbprint $NcRestCertThumbprint"
        $clusterManifestXml.ClusterManifest.Certificates.SecretsCertificate.X509FindValue = "$NcRestCertThumbprint"
        
        $securitySection = $clusterManifestXml.ClusterManifest.FabricSettings.Section | Where-Object Name -eq "Security"
        $ClusterCredentialType = $securitySection.Parameter | Where-Object Name -eq "ClusterCredentialType"
    
        $infrastructureManifestXml = [xml](Get-Content "$ManifestFolder\InfrastructureManifest.xml")
    
        # Update Node Certificate to new Node Cert if the ClusterCredentialType is X509 certificate
        if($ClusterCredentialType.Value -eq "X509")
        {
            foreach ($node in $clusterManifestXml.ClusterManifest.NodeTypes.NodeType) {
                $ncNode = $node.Name
                $ncNodeCertThumbprint = Get-NetworkControllerCertificate -NetworkController $ncNode
                Write-Verbose "Updating node $ncNode with new thumbprint $ncNodeCertThumbprint"
                $node.Certificates.ClusterCertificate.X509FindValue = "$ncNodeCertThumbprint"
                $node.Certificates.ServerCertificate.X509FindValue = "$ncNodeCertThumbprint"
                $node.Certificates.ClientCertificate.X509FindValue = "$ncNodeCertThumbprint"
            }
    
            # Update certificates InfrastructureManifest.xml
            
            foreach ($node in $infrastructureManifestXml.InfrastructureInformation.NodeList.Node) {
                $ncNode = $node.NodeName
                $ncNodeCertThumbprint = Get-NetworkControllerCertificate -NetworkController $ncNode
                $node.Certificates.ClusterCertificate.X509FindValue = "$ncNodeCertThumbprint"
                $node.Certificates.ServerCertificate.X509FindValue = "$ncNodeCertThumbprint"
                $node.Certificates.ClientCertificate.X509FindValue = "$ncNodeCertThumbprint"
            }
        }
    
        # Update certificates for settings.xml
        foreach ($ncVm in $NcVMs) {
            $settingXml = [xml](Get-Content "$ManifestFolder\$ncVm\Settings.xml")
            if($ClusterCredentialType.Value -eq "X509")
            {
                $ncNodeCertThumbprint = Get-NetworkControllerCertificate -NetworkController $ncVm
                $fabricNodeSection = $settingXml.Settings.Section | Where-Object Name -eq "FabricNode"
                $parameterToUpdate = $fabricNodeSection.Parameter | Where-Object Name -eq "ClientAuthX509FindValue"
                $parameterToUpdate.Value = "$ncNodeCertThumbprint"
                $parameterToUpdate = $fabricNodeSection.Parameter | Where-Object Name -eq "ServerAuthX509FindValue"
                $parameterToUpdate.Value = "$ncNodeCertThumbprint"
                $parameterToUpdate = $fabricNodeSection.Parameter | Where-Object Name -eq "ClusterX509FindValue"
                $parameterToUpdate.Value = "$ncNodeCertThumbprint"
            }
            $settingXml.Save("$ManifestFolderNew\$ncVm\Settings.xml")
        }
    
        $infrastructureManifestXml.Save("$ManifestFolderNew\InfrastructureManifest.xml")
        $clusterManifestXml.Save("$ManifestFolderNew\ClusterManifest.current.xml")
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}