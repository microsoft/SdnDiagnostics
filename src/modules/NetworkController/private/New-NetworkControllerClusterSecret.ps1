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
        [String]
        $OldEncryptedSecret,
        [Parameter(Mandatory = $true)]
        [String]
        $NcRestCertThumbprint,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $decryptedText = Invoke-ServiceFabricDecryptText -CipherText $OldEncryptedSecret

    if($null -eq $decryptedText)
    {
        throw New-Object System.NotSupportedException("Failed to decrypt the secret.")
    }

    $newEncryptedSecret = Invoke-ServiceFabricEncryptText -CertThumbPrint $NcRestCertThumbprint -Text $decryptedText -StoreName MY -StoreLocation LocalMachine -CertStore
    
    $newDecryptedText = Invoke-ServiceFabricDecryptText -CipherText $newEncryptedSecret

    if ($newDecryptedText -eq $decryptedText) {
        "GOOD, new key and old key are same. Ready for use" | Trace-Output
    }
    else {
        throw New-Object System.NotSupportedException("BAD, something is not right, new encrypted key does not match old one.")
    }
    if($null -eq $newEncryptedSecret)
    {
        throw New-Object System.NotSupportedException("Failed to encrypt the secret.")
    }

    return $newEncryptedSecret
}