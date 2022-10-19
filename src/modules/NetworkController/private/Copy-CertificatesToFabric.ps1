function Copy-CertificatesToFabric {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.DirectoryInfo]$CertPath,

        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$CertPassword,

        [Parameter(Mandatory = $true)]
        [System.Object]$FabricDetails,

        [Parameter(Mandatory = $false)]
        [Switch]$RotateNodeCertificates,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    begin {
        $certificateCache = @()
        $certificateConfig = @{
            NetworkController = @{}
        }

        $nodesToRotateRestCert = @()
        $nodesToRotateRestCert += $FabricDetails.NetworkController
        $nodesToRotateRestCert += $FabricDetails.SoftwareLoadBalancer
        $nodesToRotateRestCert += $FabricDetails.Server

        [System.String]$certDir = "$(Get-WorkingDirectory)\RotateCert"

        "Scanning certificates within {0}" -f $CertPath.FullName | Trace-Output
        $pfxFiles = Get-ChildItem -Path $CertPath.FullName -Filter '*.pfx'
        if ($null -eq $pfxFiles) {
            throw New-Object System.NullReferenceException("Unable to locate .pfx files under the specified CertPath location")
        }

        "Retrieving Rest Certificate" | Trace-Output
        $currentRestCertificate = Get-SdnNetworkControllerRestCertificate

        "Creating {0} directory for certificate staging on {1}" -f $certDir, ($nodesToRotateRestCert -join ', ') | Trace-Output
        Invoke-PSRemoteCommand -ComputerName $nodesToRotateRestCert -Credential $Credential -ScriptBlock {
            $null = New-Item -Path $using:certDir -ItemType Directory -Force
        } -ErrorAction Stop
    }

    process {
        foreach ($pfxFile in $pfxFiles) {
            "Retrieving PfxData for {0}" -f $pfxFile.FullName | Trace-Output
            $pfxData = Get-PfxData -FilePath $pfxFile.FullName -Password $CertPassword -ErrorAction Stop

            $object = [PSCustomObject]@{
                FileInfo = $pfxFile
                PfxData = $pfxData
            }

            $certificateCache += $object
        }

        # enumerate the current certificates within the cache to isolate the rest certificate
        foreach ($cert in $certificateCache) {
            if ($cert.pfxdata.EndEntityCertificates.Subject -ieq $currentRestCertificate.Subject) {
                "Matched {0} [Subject: {1}; Thumbprint: {2}] to NC Rest Certificate" -f `
                $cert.pfxFile.FileInfo.FullName,  $cert.pfxData.EndEntityCertificates.Subject, $cert.pfxData.EndEntityCertificates.Thumbprint | Trace-Output

                $restCertificate = $cert
                break
            }
        }

        # install the rest certificate to Network Controllers, MUXes and Servers
        # if the certificate is self signed, it will automatically install to the root store as part of the process
        if ($restCertificate) {
            foreach ($node in $nodesToRotateRestCert) {
                "Installing {0} to {1}" -f $restcertificate.pfxData.EndEntityCertificates.Thumbprint, $node | Trace-Output
                [System.String]$remoteFilePath = Join-Path -Path $certDir -ChildPath $restCertificate.FileInfo.BaseName
                Copy-FileToRemoteComputer -ComputerName $node -Credential $Credential -Path $restCertificate.FileInfo.FullName -Destination $remoteFilePath

                $null = Invoke-PSRemoteCommand -ComputerName $node -Credential $Credential -ScriptBlock {
                    Import-SdnCertificate -FilePath $using:remoteFilePath -CertPassword $using:CertPassword
                }
            }
        }

        # if we declared to rotate the network controller node certificates
        # we will want to process and perform the import of the certificates to the appropriate nodes
        if ($RotateNodeCertificates) {

            # enumerate the certificates for network controller nodes
            foreach($node in $sdnFabricDetails.NetworkController) {
                "Retrieving current node certificate for {0}" -f $node | Trace-Output
                $currentNodeCert = Invoke-PSRemoteCommand -ComputerName $node -Credential $Credential -ScriptBlock { Get-SdnNetworkControllerNodeCertificate } -ErrorAction Stop
                foreach ($cert in $certificateCache) {
                    $updatedNodeCert = $null
                    if ($cert.PfxData.EndEntityCertificates.Subject -ieq $currentNodeCert.Subject) {
                        $updatedNodeCert = $cert
                        "Matched {0} [Subject: {1}; Thumbprint: {2}] to {3}" -f `
                        $updatedNodeCert.FileInfo.Name, $cert.PfxData.EndEntityCertificates.Subject, $cert.PfxData.EndEntityCertificates.Thumbprint, $node | Trace-Output

                        break
                    }
                }

                $certificateConfig.NetworkController[$node] = @{
                    Cert = $updatedNodeCert
                }
            }

            foreach ($node in $sdnFabricDetails.NetworkController) {

                $nodeCertConfig = $certificateConfig.NetworkController[$node]
                Copy-FileToRemoteComputer -ComputerName $node -Credential $Credential -Path $nodeCertConfig.UpdatedCert.FileInfo.FullName -Destination $certDir
                "Importing {0} to {1}" -f $nodeCertConfig.UpdatedCert.PfxData.EndEntityCertificates.Thumbprint, $node | Trace-Output
                [System.String]$remoteFilePath = Join-Path -Path $certDir -ChildPath $restCertificate.FileInfo.BaseName

                $certImport = Invoke-PSRemoteCommand -ComputerName $node -Credential $Credential -ScriptBlock {
                    Import-SdnCertificate -FilePath $using:remoteFilePath -CertPassword $using:CertPassword
                } -ErrorAction Stop

                # if self signed was defined, we need to take a copy of the .cer file we exported
                # to copy to the other network controller VMs
                if ($certImport.SelfSigned) {
                    [System.String]$nodeCerFile = Join-Path -Path $certDir -ChildPath $certImport.CerFile.FileInfo.BaseName
                    Copy-FileFromRemoteComputer -ComputerName $node -Credential $Credential -Path $certImport.CerFile.FileInfo.FullName -Destination $nodeCerFile
                    foreach ($controller in $sdnFabricDetails.NetworkController) {
                        "Importing certificate {0} to {1}" -f $nodeCertConfig.UpdatedCert.PfxData.EndEntityCertificates.Thumbprint, $controller | Trace-Output
                        Copy-FileToRemoteComputer -ComputerName $controller -Credential $Credential -Path $nodeCerFile -Destination $nodeCerFile
                        Invoke-PSRemoteCommand -ComputerName $controller -Credential $Credential -ScriptBlock {
                            $cert = Get-ChildItem -Path $using:nodeCerFile
                            $null = Import-Certificate -FilePath $cert.FullName -CertStoreLocation "Cert:\LocalMachine\Root"
                        } -ErrorAction Stop
                    }
                }
            }
        }
    }
    end {
        # nothing here
    }
}
