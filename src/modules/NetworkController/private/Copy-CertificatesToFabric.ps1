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
        $southBoundNodes = @()

        $nodesToRotateRestCert += $FabricDetails.NetworkController

        if($null -ne $FabricDetails.SoftwareLoadBalancer){
            $nodesToRotateRestCert += $FabricDetails.SoftwareLoadBalancer
            $southBoundNodes += $FabricDetails.SoftwareLoadBalancer
        }
        
        if($null -ne $FabricDetails.Server){
            $nodesToRotateRestCert += $FabricDetails.Server
            $southBoundNodes += $FabricDetails.Server
        }

        [System.String]$certDir = "$(Get-WorkingDirectory)\RotateCert"

        "Scanning certificates within {0}" -f $CertPath.FullName | Trace-Output
        $pfxFiles = Get-ChildItem -Path $CertPath.FullName -Filter '*.pfx'
        if ($null -eq $pfxFiles) {
            throw New-Object System.NullReferenceException("Unable to locate .pfx files under the specified CertPath location")
        }

        "Retrieving Rest Certificate" | Trace-Output -Level:Verbose
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
                $cert.pfxFile.FileInfo.FullName,  $cert.pfxData.EndEntityCertificates.Subject, $cert.pfxData.EndEntityCertificates.Thumbprint | Trace-Output -Level:Verbose

                $restCertificate = $cert
                break
            }
        }

        # install the rest certificate to Network Controllers
        if ($null -eq $restCertificate) {
            throw New-Object System.NullReferenceException("Unable to locate rest certificate")
        }

        # copy the pfx certificate for the rest certificate to all network controllers within the cluster
        # and import to localmachine\my cert directory
        foreach ($controller in $FabricDetails.NetworkController) {
            "Importing rest certificate [Subject: {0} Thumbprint:{1}] to {2}" -f `
            $restcertificate.pfxData.EndEntityCertificates.Subject, $restcertificate.pfxData.EndEntityCertificates.Thumbprint, $controller | Trace-Output

            [System.String]$remoteFilePath = Join-Path -Path $certDir -ChildPath $restCertificate.FileInfo.Name
            Copy-FileToRemoteComputer -ComputerName $controller -Credential $Credential -Path $restCertificate.FileInfo.FullName -Destination $remoteFilePath

            $importRestCert = Invoke-PSRemoteCommand -ComputerName $controller -Credential $Credential -ScriptBlock {
                Import-SdnCertificate -FilePath $using:remoteFilePath -CertPassword $using:CertPassword -CertStore 'Cert:\LocalMachine\My'
            }

            # if the certificate was detected as self signed
            # then check to see if the controller we install the cert on is local
            # we will then copy the .cer file returned from the previous command to all the southbound nodes to install
            if ($importRestCert.SelfSigned) {
                if (Test-ComputerNameIsLocal -ComputerName $controller) {
                    foreach ($sbNode in $southBoundNodes) {
                        [System.String]$remoteFilePath = Join-Path -Path $certDir -ChildPath $importRestCert.CerFileInfo.Name
                        Copy-FileToRemoteComputer -ComputerName $sbNode -Credential $Credential -Path $importRestCert.CerFileInfo.FullName -Destination $remoteFilePath
                        $null = Invoke-PSRemoteCommand -ComputerName $sbNode -Credential $Credential -ScriptBlock {
                            Import-SdnCertificate -FilePath $using:remoteFilePath -CertStore 'Cert:\LocalMachine\Root'
                        } -ErrorAction Stop
                    }
                }
            }
        }

        # if we declared to rotate the network controller node certificates
        # we will want to process and perform the import of the certificates to the appropriate nodes
        if ($RotateNodeCertificates) {

            # enumerate the certificates for network controller nodes
            foreach($node in $FabricDetails.NetworkController) {
                "Retrieving current node certificate for {0}" -f $node | Trace-Output -Level:Verbose
                $currentNodeCert = Invoke-PSRemoteCommand -ComputerName $node -Credential $Credential -ScriptBlock { Get-SdnNetworkControllerNodeCertificate } -ErrorAction Stop
                foreach ($cert in $certificateCache) {
                    $updatedNodeCert = $null
                    if ($cert.PfxData.EndEntityCertificates.Subject -ieq $currentNodeCert.Subject) {
                        $updatedNodeCert = $cert
                        "Matched {0} [Subject: {1}; Thumbprint: {2}] to {3}" -f `
                        $updatedNodeCert.FileInfo.Name, $cert.PfxData.EndEntityCertificates.Subject, $cert.PfxData.EndEntityCertificates.Thumbprint, $node | Trace-Output -Level:Verbose

                        break
                    }
                }

                $certificateConfig.NetworkController[$node] = @{
                    Cert = $updatedNodeCert
                }
            }

            # copy the respective node pfx certificates for each of the network controllers
            foreach ($node in $FabricDetails.NetworkController) {
                $nodeCertConfig = $certificateConfig.NetworkController[$node]
                [System.String]$remoteFilePath = Join-Path -Path $certDir -ChildPath $nodeCertConfig.Cert.FileInfo.Name
                Copy-FileToRemoteComputer -ComputerName $node -Credential $Credential -Path $nodeCertConfig.Cert.FileInfo.FullName -Destination $remoteFilePath

                "Importing node certificate [Subject: {0} Thumbprint:{1}] to {2}" -f `
                $nodeCertConfig.Cert.PfxData.EndEntityCertificates.Subject, $nodeCertConfig.Cert.PfxData.EndEntityCertificates.Thumbprint, $node | Trace-Output

                $importNodeCert = Invoke-PSRemoteCommand -ComputerName $node -Credential $Credential -ScriptBlock {
                    Import-SdnCertificate -FilePath $using:remoteFilePath -CertPassword $using:CertPassword -CertStore 'Cert:\LocalMachine\My'
                } -ErrorAction Stop

                # if self signed was defined, we need to take a copy of the .cer file we exported
                # to copy to the other network controller VMs
                if ($importNodeCert.SelfSigned) {
                    [System.String]$nodeCerFile = Join-Path -Path $certDir -ChildPath $importNodeCert.CerFileInfo.Name
                    if (-NOT (Test-Path -Path $nodeCerFile -PathType Leaf)) {
                        Copy-FileFromRemoteComputer -ComputerName $node -Credential $Credential -Path $importNodeCert.CerFileInfo.FullName -Destination $certDir
                    }

                    foreach ($controller in ($sdnFabricDetails.NetworkController | Where-Object {$_ -ine $node})) {
                        "Importing self signed node certificate [Subject: {0} Thumbprint:{1}] to {2}" -f `
                        $nodeCertConfig.Cert.PfxData.EndEntityCertificates.Subject, $nodeCertConfig.Cert.PfxData.EndEntityCertificates.Thumbprint, $controller | Trace-Output

                        Copy-FileToRemoteComputer -ComputerName $controller -Credential $Credential -Path $nodeCerFile -Destination $nodeCerFile
                        $null = Invoke-PSRemoteCommand -ComputerName $controller -Credential $Credential -ScriptBlock {
                            Import-SdnCertificate -FilePath $using:nodeCerFile -CertStore 'Cert:\LocalMachine\Root'
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
