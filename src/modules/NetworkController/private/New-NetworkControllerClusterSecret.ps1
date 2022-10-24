# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function New-NetworkControllerClusterSecret {
    <#
    .SYNOPSIS
        Decrypt the current secret in ClusterManifest and Generate new one if decrypt success.
    .PARAMETER NcVMs
        The list of Network Controller VMs.
	.PARAMETER NcRestName
		The Network Controller REST Name in FQDN format.
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
        $ManifestFolder,
        [Parameter(Mandatory = $true)]
        [String]
        $ManifestFolderNew,
        [Parameter(Mandatory = $true)]
        [String]
        $NcRestCertThumbprint,
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
        # Get encrypted secret from Cluster Manifest
        $clusterManifestXml = [xml](Get-Content "$ManifestFolderNew\ClusterManifest.current.xml")
        $fileStoreServiceSection = ($clusterManifestXml.ClusterManifest.FabricSettings.Section | Where-Object name -eq FileStoreService)
        $primaryEncryptedSecret = ($fileStoreServiceSection.Parameter | Where-Object Name -eq "PrimaryAccountNTLMPasswordSecret").Value
        #$ncRestCertThumprint = Get-NcNodeCertificateThumbprint -NetworkController $NcVMs[0] -NcRestName $NcRestName
        $newEncryptedSecret = Invoke-Command -ComputerName $NcVMs[0] -ScriptBlock {
            $primaryText = Invoke-ServiceFabricDecryptText -CipherText $using:primaryEncryptedSecret
    
            if($null -eq $primaryText)
            {
                Trace-Output "Failed to decrypt the secret." -Level:Error
                return $null
            }
    
            $newKey = Invoke-ServiceFabricEncryptText -CertThumbPrint $using:NcRestCertThumbprint -Text $primaryText -StoreName MY -StoreLocation LocalMachine -CertStore
            
            $newKeyText = Invoke-ServiceFabricDecryptText -CipherText $newKey
        
            if ($primaryText -eq $newKeyText) {
                Write-Host "GOOD, new key and old key are same. Ready for use" -ForegroundColor Green
                return $newKey
            }
            else {
                Write-Error "BAD, something is not right, new encrypted key does not match old one." -Level:Error
                return $null
            }
        } -Credential $Credential
    
        if($null -eq $newEncryptedSecret)
        {
            # Do not update the cluster manifest if secret is empty
            return $false
        }
        # Update new encrypted secret in Cluster Manifest
        ($fileStoreServiceSection.Parameter | Where-Object Name -eq "PrimaryAccountNTLMPasswordSecret").Value = "$newEncryptedSecret"
        ($fileStoreServiceSection.Parameter | Where-Object Name -eq "SecondaryAccountNTLMPasswordSecret").Value = "$newEncryptedSecret"
        $clusterManifestXml.Save("$ManifestFolderNew\ClusterManifest.current.xml")
    
        # Update certificates for settings.xml
        foreach ($ncVm in $NcVMs) {
            $settingXml = [xml](Get-Content "$ManifestFolderNew\$ncVm\Settings.xml")
            $fileStoreServiceSection = $settingXml.Settings.Section | Where-Object Name -eq "FileStoreService"
            ($fileStoreServiceSection.Parameter | Where-Object Name -eq "PrimaryAccountNTLMPasswordSecret").Value = "$newEncryptedSecret"
            ($fileStoreServiceSection.Parameter | Where-Object Name -eq "SecondaryAccountNTLMPasswordSecret").Value = "$newEncryptedSecret"    
            $settingXml.Save("$ManifestFolderNew\$ncVm\Settings.xml")
        }
    
        return $true
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}