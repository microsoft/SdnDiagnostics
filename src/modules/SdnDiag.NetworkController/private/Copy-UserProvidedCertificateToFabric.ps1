# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.


function Copy-UserProvidedCertificateToFabric {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.DirectoryInfo]$CertPath,

        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$CertPassword,

        [Parameter(Mandatory = $true)]
        [System.Object]$FabricDetails,

        [Parameter(Mandatory = $false)]
        [System.Boolean]$RotateNodeCerts = $false,

        [Parameter(Mandatory = $false)]
        [System.Boolean]$NetworkControllerHealthy = $false,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $certificateCache = @()
    $certificateConfig = @{
        RestCert          = $null
        NetworkController = @{}
    }

    "Scanning certificates within {0}" -f $CertPath.FullName | Trace-Output
    $pfxFiles = Get-ChildItem -Path $CertPath.FullName -Filter '*.pfx'
    if ($null -eq $pfxFiles) {
        throw New-Object System.NullReferenceException("Unable to locate .pfx files under the specified CertPath location")
    }

    foreach ($pfxFile in $pfxFiles) {
        "Retrieving PfxData for {0}" -f $pfxFile.FullName | Trace-Output
        $pfxData = Get-PfxData -FilePath $pfxFile.FullName -Password $CertPassword -ErrorAction Stop

        $object = [PSCustomObject]@{
            FileInfo = $pfxFile
            PfxData  = $pfxData
            SelfSigned = $false
        }

        $certificateCache += $object
    }

    "Retrieving Rest Certificate" | Trace-Output -Level:Verbose
    $currentRestCertificate = Get-SdnNetworkControllerRestCertificate

    # enumerate the current certificates within the cache to isolate the rest certificate
    foreach ($cert in $certificateCache) {
        if ($cert.pfxdata.EndEntityCertificates.Subject -ieq $currentRestCertificate.Subject) {
            "Matched {0} [Subject: {1}; Thumbprint: {2}] to NC Rest Certificate" -f `
                $cert.pfxFile.FileInfo.FullName, $cert.pfxData.EndEntityCertificates.Subject, $cert.pfxData.EndEntityCertificates.Thumbprint | Trace-Output -Level:Verbose

            $cert | Add-Member -MemberType NoteProperty -Name 'CertificateType' -Value 'NetworkControllerRest'
            $restCertificate = $cert
            $certificateConfig.RestCert = $restCertificate.pfxData.EndEntityCertificates.Thumbprint
        }

        if ($cert.pfxdata.EndEntityCertificates.Subject -ieq $cert.pfxdata.EndEntityCertificates.Issuer) {
            $cert.SelfSigned = $true
        }
    }

    # enumerate the certificates for network controller nodes
    if ($RotateNodeCerts) {
        foreach ($node in $FabricDetails.NetworkController) {
            "Retrieving current node certificate for {0}" -f $node | Trace-Output
            $currentNodeCert = Invoke-PSRemoteCommand -ComputerName $node -Credential $Credential -ScriptBlock { Get-SdnNetworkControllerNodeCertificate } -ErrorAction Stop
            foreach ($cert in $certificateCache) {
                $updatedNodeCert = $null
                if ($cert.PfxData.EndEntityCertificates.Subject -ieq $currentNodeCert.Subject) {
                    $updatedNodeCert = $cert
                    "Matched {0} [Subject: {1}; Thumbprint: {2}] to {3}" -f `
                        $updatedNodeCert.FileInfo.Name, $cert.PfxData.EndEntityCertificates.Subject, $cert.PfxData.EndEntityCertificates.Thumbprint, $node | Trace-Output

                    $cert | Add-Member -MemberType NoteProperty -Name 'CertificateType' -Value 'NetworkControllerNode'
                    break
                }
            }

            $certificateConfig.NetworkController[$node] = @{
                Cert = $updatedNodeCert
            }
        }
    }

    # install the rest certificate to the network controllers to this node first
    # then seed out to the rest of the fabric
    $null = Import-SdnCertificate -FilePath $restCertificate.FileInfo.FullName -CertPassword $CertPassword -CertStore 'Cert:\LocalMachine\My'
    Copy-CertificateToFabric -CertFile $restCertificate.FileInfo.FullName -CertPassword $CertPassword -FabricDetails $FabricDetails `
    -NetworkControllerRestCertificate -InstallToSouthboundDevices:$NetworkControllerHealthy -Credential $Credential

    # install the nc node certificate to other network controller nodes if self-signed
    if ($RotateNodeCerts) {
        foreach ($controller in $FabricDetails.NetworkController) {
            "Processing {0} for node certificates" -f $controller | Trace-Output -Level:Verbose
            $nodeCertConfig = $certificateConfig.NetworkController[$controller]

            # if we have identified a network controller node certificate then proceed
            # with installing the cert locally (if matches current node)
            if ($null -ne $nodeCertConfig.Cert.FileInfo.FullName) {
                if (Test-ComputerNameIsLocal -ComputerName $controller) {
                    $null = Import-SdnCertificate -FilePath $nodeCertConfig.Cert.FileInfo.FullName -CertPassword $CertPassword -CertStore 'Cert:\LocalMachine\My'
                }


                # pass the certificate to sub-function to be seeded across the fabric if necassary
                Copy-CertificateToFabric -CertFile $nodeCertConfig.Cert.FileInfo.FullName -CertPassword $CertPassword -FabricDetails $FabricDetails -NetworkControllerNodeCert -Credential $Credential
            }
            else {
                "Unable to locate self-signed certificate file for {0}. Node certificate may need to be manually installed to other Network Controllers manually." -f $controller | Trace-Output -Level:Exception
            }
        }
    }

    return $certificateCache
}
