# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Start-SdnCertificateRotation {
    <#
    .SYNOPSIS
        Performs a controller certificate rotate operation for Network Controller Northbound API, Southbound communications and Network Controller nodes.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $false, ParameterSetName = 'SelfSigned')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $false, ParameterSetName = 'SelfSigned')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Pfx')]
        [System.IO.DirectoryInfo]$CertPath,

        [Parameter(Mandatory = $false, ParameterSetName = 'SelfSigned')]
        [Switch]$GenerateCertificate,

        [Parameter(Mandatory = $true, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $true, ParameterSetName = 'SelfSigned')]
        [System.Security.SecureString]$CertPassword
    )

    $config = Get-SdnRoleConfiguration -Role 'NetworkController'
    $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
    if (-NOT ($confirmFeatures)) {
        throw New-Object System.NotSupportedException("The current machine is not a NetworkController, run this on NetworkController.")
    }

    try {
        "Starting certificate rotation" | Trace-Output
        "Retrieving current SDN environment details" | Trace-Output

        # determine fabric information and current version settings for network controller
        $sdnFabricDetails = Get-SdnInfrastructureInfo -NetworkController $env:COMPUTERNAME -Credential $Credential -NcRestCredential $NcRestCredential
        $ncSettings = @{
            NetworkControllerVersion        = (Get-NetworkController).Version
            NetworkControllerClusterVersion = (Get-NetworkControllerCluster).Version
        }

        # before we proceed with anything else, we want to make sure that all the Network Controllers within the SDN fabric are running the current version
        Install-SdnDiagnostics -ComputerName $sdnFabricDetails.NetworkController -ErrorAction Stop

        "Network Controller version: {0}" -f $ncSettings.NetworkControllerVersion | Trace-Output
        "Network Controller cluster version: {0}" -f $ncSettings.NetworkControllerClusterVersion | Trace-Output

        $healthState = Get-SdnServiceFabricClusterHealth -NetworkController $env:COMPUTERNAME
        if ($healthState.AggregatedHealthState -ine 'Ok') {
            "Service Fabric AggregatedHealthState is currently reporting {0}" -f $healthState.AggregatedHealthState | Trace-Output -Level:Exception
            return
        }

        #####################################
        #
        # Create Certificate (Optional)
        #
        #####################################

        if ($GenerateCertificate) {
            "== STAGE: CREATE SELF SIGNED CERTIFICATES ==" | Trace-Output

            # generate the NC REST Certificate
            [System.String]$path = "$(Get-WorkingDirectory)\Cert_{0}" -f (Get-FormattedDateTimeUTC)
            "Creating directory {0}" -f $path | Trace-Output
            [System.IO.DirectoryInfo]$CertPath = New-Item -Path $path -ItemType Directory -Force

            $restCertSubject = (Get-SdnNetworkControllerRestCertificate).Subject
            $restCert = New-SdnCertificate -Subject $restCertSubject -NotAfter (Get-Date).AddDays(365)

            # after the certificate has been generated, we want to export the certificate using the $CertPassword provided by the operator
            # and save the file to directory. This allows the rest of the function to pick up these files and perform the steps as normal
            [System.String]$filePath = "$(Join-Path -Path $CertPath.FullName -ChildPath $restCertSubject.ToString().ToLower().Replace('.','_').Replace('=','_').Trim()).pfx"
            "Exporting pfx certificate to {0}" -f $filePath | Trace-Output
            $null = Export-PfxCertificate -Cert $restCert -FilePath $filePath -Password $CertPassword -CryptoAlgorithmOption AES256_SHA256

            # generate NC node certificates
            foreach ($controller in $sdnFabricDetails.NetworkController) {
                if (Test-ComputerNameIsLocal -ComputerName $controller) {
                    $nodeCertSubject = (Get-SdnNetworkControllerNodeCertificate).Subject
                }
                else {
                    $nodeCertSubject = Invoke-PSRemoteCommand -ComputerName $controller -Credential $Credential -ScriptBlock { (Get-SdnNetworkControllerNodeCertificate).Subject }
                }

                $selfSignedCert = New-SdnCertificate -Subject $nodeCertSubject -NotAfter (Get-Date).AddDays(365)

                # after the certificate has been generated, we want to export the certificate using the $CertPassword provided by the operator
                # and save the file to directory. This allows the rest of the function to pick up these files and perform the steps as normal
                [System.String]$filePath = "$(Join-Path -Path $CertPath.FullName -ChildPath $controller.ToString().ToLower().Replace('.','_').Trim()).pfx"
                "Exporting pfx certificate to {0}" -f $filePath | Trace-Output
                $null = Export-PfxCertificate -Cert $selfSignedCert -FilePath $filePath -Password $CertPassword -CryptoAlgorithmOption AES256_SHA256
            }
        }

        #####################################
        #
        # Certificate Configuration
        #
        #####################################

        "== STAGE: DETERMINE CERTIFICATE CONFIGURATION ==" | Trace-Output

        $certificateCache = @()
        $certificateConfig = @{
            NetworkController = @{}
        }

        "Scanning certificates within {0}" -f $CertPath.FullName | Trace-Output
        $pfxFiles = Get-ChildItem -Path $CertPath.FullName -Filter '*.pfx'
        if ($null -eq $pfxFiles) {
            throw New-Object System.NullReferenceException("Unable to locate .pfx files under the specified CertPath location")
        }

        # parse each of the pfx files and store in variable
        foreach ($pfxFile in $pfxFiles) {
            "Retrieving PfxData for {0}" -f $pfxFile.FullName | Trace-Output
            $pfxData = Get-PfxData -FilePath $pfxFile.FullName -Password $CertPassword -ErrorAction Stop

            # determine if the certificates being used are self signed
            if ($pfxData.EndEntityCertificates.Subject -ieq $pfxData.EndEntityCertificates.Issuer) {
                "Detected the certificate subject and issuer are the same. Setting SelfSigned to true" | Trace-Output
                $SelfSigned = $true
            }
            else {
                "Detected the certificate has been issued by a CA" | Trace-Output
                $SelfSigned = $false
            }

            $object = [PSCustomObject]@{
                FileInfo = $pfxFile
                PfxData = $pfxData
                SelfSigned = $SelfSigned
            }

            $certificateCache += $object
        }

        # enumerate the NC REST certificates
        "Retrieving Rest Certificate" | Trace-Output
        $currentRestCertificate = Get-SdnNetworkControllerRestCertificate
        if ($currentRestCertificate.NotAfter -le (Get-Date)) {
            $certIsExpired = $true
            "[Thumbprint: {0}] NC REST certificate is expired" -f $currentRestCertificate.Thumbprint | Trace-Output -Level:Warning
        }

        foreach ($cert in $certificateCache) {
            if ($cert.PfxData.EndEntityCertificates.Subject -ieq $currentRestCertificate.Subject) {
                $updatedRestCertificate = $cert
                "Matched {0} [Subject: {1}; Thumbprint: {2}] to NC Rest Certificate" -f `
                $cert.FileInfo.FullName,  $cert.PfxData.EndEntityCertificates.Subject, $cert.PfxData.EndEntityCertificates.Thumbprint | Trace-Output

                if ($cert.PfxData.EndEntityCertificates.Subject -ieq $currentRestCertificate.Issuer) {
                    "Detected the REST certificate subject and issuer are the same. Setting SelfSigned to true" | Trace-Output
                    $restCertificateSelfSigned = $true
                }

                break
            }
        }

        # enumerate the NC node certificates
        foreach($node in $sdnFabricDetails.NetworkController) {
            "Retrieving current node certificate for {0}" -f $node | Trace-Output
            $currentNodeCert = Invoke-PSRemoteCommand -ComputerName $node -Credential $Credential -ScriptBlock { Get-SdnNetworkControllerNodeCertificate } -ErrorAction Stop
            if ($currentNodeCert.NotAfter -le (Get-Date)) {
                $certIsExpired = $true
                "[Thumbprint: {0}] {1} certificate is expired" -f $currentNodeCert.Thumbprint, $node | Trace-Output -Level:Warning
            }

            foreach ($cert in $certificateCache) {
                $updatedNodeCert = $null
                if ($cert.PfxData.EndEntityCertificates.Subject -ieq $currentNodeCert.Subject) {
                    $updatedNodeCert = $cert
                    "Matched {0} [Subject: {1}; Thumbprint: {2}] to {3}" -f `
                    $updatedNodeCert.FileInfo.Name, $cert.PfxData.EndEntityCertificates.Subject, $cert.PfxData.EndEntityCertificates.Thumbprint, $node | Trace-Output

                    break
                }
            }

            # if we cannot locate the certificate that we expect, terminate the function
            if ($null -eq $updatedNodeCert) {
                throw System.NullReferenceException("Unable to locate new node certificate for $($node)")
            }

            $certificateConfig.NetworkController[$node] = @{
                CurrentCert = $currentNodeCert
                UpdatedCert = $updatedNodeCert
            }
        }

        # make sure that none of the current certificates are expired
        # there is more advanced remediation steps required to unblock this scenario that this function does not handle currently
        if ($certIsExpired) {
            "Network Controller certificates are expired" | Trace-Output -Level:Error
            return
        }

        #####################################
        #
        # Certificate Seeding
        #
        #####################################

        "== STAGE: CERTIFICATE SEEDING ==" | Trace-Output

        [System.String]$certDir = "$(Get-WorkingDirectory)\RotateCerts"

        $nodesToRotate = @()
        $nodesToRotate += $sdnFabricDetails.NetworkController
        $nodesToRotate += $sdnFabricDetails.Server
        $nodesToRotate += $sdnFabricDetails.SoftwareLoadBalancer

        $southBoundNodes = @()
        $southBoundNodes += $sdnFabricDetails.Server
        $southBoundNodes += $sdnFabricDetails.SoftwareLoadBalancer

        "Creating {0} directory for certificate staging on {1}" -f $certDir, ($nodesToRotate -join ', ') | Trace-Output
        Invoke-PSRemoteCommand -ComputerName $nodesToRotate -Credential $Credential -ScriptBlock {
            # create the directory and if present, just overwrite
            $null = New-Item -Path $using:certDir -ItemType Directory -Force
        } -ErrorAction Stop

        # install the rest certificate
        foreach ($node in $sdnFabricDetails.NetworkController) {
            Copy-FileToRemoteComputer -ComputerName $node -Credential $Credential -Path $updatedRestCertificate.FileInfo.FullName -Destination $certDir

            "[{0}]: Importing {1}" -f $node, $updatedRestCertificate.PfxData.EndEntityCertificates.Thumbprint | Trace-Output
            Invoke-PSRemoteCommand -ComputerName $node -Credential $Credential -ScriptBlock {
                $pfxCertToInstall = Get-ChildItem -Path $using:certDir | Where-Object {$_.Name -ieq $using:updatedRestCertificate.FileInfo.Name}
                $pfxCertificate = Import-PfxCertificate -FilePath $pfxCertToInstall.FullName -CertStoreLocation 'Cert:\LocalMachine\My' -Password $using:CertPassword -Exportable -ErrorAction Stop

                Set-SdnCertificateAcl -Path 'Cert:\LocalMachine\My' -Thumbprint $($pfxCertificate.Thumbprint).ToString()
            } -ErrorAction Stop
        }

        # if $SelfSigned, we need to take a copy of the REST certificate .cer file we exported
        # in previous steps, and install a copy on the servers and muxes for southbound communication
        if ($restCertificateSelfSigned) {
            "Rest certificate is self-signed. Importing the public key of the rest certificate to root store" -f $node | Trace-Output
            $pfxCertificate = Get-ChildItem -Path 'Cert:\LocalMachine\My' | Where-Object {$_.Thumbprint -ieq $updatedRestCertificate.PfxData.EndEntityCertificates.Thumbprint}
            $cerFile = Export-Certificate -Type CERT -FilePath "$certDir\NC_Rest.cer" -Cert $pfxCertificate
            foreach ($node in $southBoundNodes) {
                Copy-FileToRemoteComputer -ComputerName $node -Credential $Credential -Path $cerFile.FullName -Destination $cerFile.FullName
                "Importing certificate {0} to {1}" -f $cerFile.FullName, $node | Trace-Output
                Invoke-PSRemoteCommand -ComputerName $node -Credential $Credential -ScriptBlock {
                    $null = Import-Certificate -FilePath $using:cerFile.FullName -CertStoreLocation "Cert:\LocalMachine\Root"
                } -ErrorAction Stop
            }
        }

        # install the node certificates
        foreach ($node in $sdnFabricDetails.NetworkController) {
            $nodeCertConfig = $certificateConfig.NetworkController[$node]
            Copy-FileToRemoteComputer -ComputerName $node -Credential $Credential -Path $nodeCertConfig.UpdatedCert.FileInfo.FullName -Destination $certDir

            "Importing {0} to {1}" -f $nodeCertConfig.UpdatedCert.PfxData.EndEntityCertificates.Thumbprint, $node | Trace-Output
            Invoke-PSRemoteCommand -ComputerName $node -Credential $Credential -ScriptBlock {
                $pfxCertToInstall = Get-ChildItem -Path $using:certDir | Where-Object {$_.Name -ieq $using:nodeCertConfig.UpdatedCert.FileInfo.Name}
                $pfxCertificate = Import-PfxCertificate -FilePath $pfxCertToInstall.FullName -CertStoreLocation 'Cert:\LocalMachine\My' -Password $using:CertPassword -Exportable -ErrorAction Stop

                Set-SdnCertificateAcl -Path 'Cert:\LocalMachine\My' -Thumbprint $pfxCertificate.Thumbprint
            } -ErrorAction Stop

            # if self signed was defined, we need to take a copy of the .cer file we exported
            # to copy to the other network controller VMs
            if ($nodeCertConfig.UpdatedCert.SelfSigned) {
                $filePath = "$certDir\$controller.cer"
                "{0} is self-signed. Importing the public key to root store" -f $nodeCertConfig.UpdatedCert.PfxData.EndEntityCertificates.Thumbprint | Trace-Output
                $nodeCerFile = Export-Certificate -Type CERT -FilePath $filePath -Cert $pfxCertificate

                foreach ($controller in $sdnFabricDetails.NetworkController) {
                    "Importing certificate {0} to {1}" -f $nodeCertConfig.UpdatedCert.PfxData.EndEntityCertificates.Thumbprint, $controller | Trace-Output
                    if (Test-ComputerNameIsLocal -ComputerName $controller) {
                        $null = Import-Certificate -FilePath $nodeCerFile.FullName -CertStoreLocation "Cert:\LocalMachine\Root"
                    }
                    else {
                        Copy-FileToRemoteComputer -ComputerName $controller -Credential $Credential -Path $nodeCerFile.FullName -Destination $nodeCerFile.FullName
                        Invoke-PSRemoteCommand -ComputerName $controller -Credential $Credential -ScriptBlock {
                            $pfxCertificate = Get-ChildItem -Path $using:certDir | Where-Object {$_.Name -ieq $using:nodeCertConfig.UpdatedCert.PfxData.EndEntityCertificates.Thumbprint}
                            $null = Import-Certificate -FilePath $pfxCertificate.FullName -CertStoreLocation "Cert:\LocalMachine\Root"
                        } -ErrorAction Stop
                    }
                }
            }
        }

        #####################################
        #
        # Rotate NC Northbound Certificate (REST)
        #
        #####################################

        "== STAGE: ROTATE NC REST CERTIFICATE ==" | Trace-Output

        $null = Invoke-CertRotateCommand -Command 'Set-NetworkController' -Credential $Credential -Thumbprint $updatedRestCertificate.PfxData.EndEntityCertificates.Thumbprint

        "Waiting for 5 minutes before proceeding to the next step. Script will resume at {0}" -f (Get-Date).AddMinutes(5).ToUniversalTime().ToString() | Trace-Output
        Start-Sleep -Seconds 300

        #####################################
        #
        # Rotate Cluster Certificate
        #
        #####################################

        "== STAGE: ROTATE NC CLUSTER CERTIFICATE ==" | Trace-Output

        $null = Invoke-CertRotateCommand -Command 'Set-NetworkControllerCluster' -Credential $Credential -Thumbprint $updatedRestCertificate.PfxData.EndEntityCertificates.Thumbprint

        "Waiting for 5 minutes before proceeding to the next step. Script will resume at {0}" -f (Get-Date).AddMinutes(5).ToUniversalTime().ToString() | Trace-Output
        Start-Sleep -Seconds 300

        #####################################
        #
        # Rotate NC Node Certificates
        #
        #####################################

        "== STAGE: ROTATE NC NODE CERTIFICATE ==" | Trace-Output

        foreach ($node in $sdnFabricDetails.NetworkController){
            $nodeCertConfig = $certificateConfig.NetworkController[$node]
            $null = Invoke-CertRotateCommand -Command 'Set-NetworkControllerNode' -NetworkController $node -Credential $Credential -Thumbprint $nodeCertConfig.UpdatedCert.PfxData.EndEntityCertificates.Thumbprint

            "Waiting for 2 minutes before proceeding to the next step. Script will resume at {0}" -f (Get-Date).AddMinutes(5).ToUniversalTime().ToString() | Trace-Output
            Start-Sleep -Seconds 120
        }

        #####################################
        #
        # Rotate NC Southbound Certificates
        #
        #####################################

        $headers = @{"Accept"="application/json"}
        $content = "application/json; charset=UTF-8"
        $timeoutInMinutes = 5

        "== STAGE: ROTATE SOUTHBOUND CERTIFICATE CREDENTIALS ==" | Trace-Output

        $allCredentials = Get-SdnResource -ResourceType Credentials -Credential $NcRestCredential -NcUri $sdnFabricDetails.NcUrl
        foreach ($cred in $allCredentials) {
            $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

            if ($cred.properties.type -eq "X509Certificate") {

                # if for any reason the certificate thumbprint has been updated, then skip the update operation for this credential resource
                if ($cred.properties.value -ieq $updatedRestCertificate.PfxData.EndEntityCertificates.Thumbprint) {
                    "{0} has already been configured to {1}" -f $cred.resourceRef, $updatedRestCertificate.PfxData.EndEntityCertificates.Thumbprint | Trace-Output
                    continue
                }

                "{0} will be updated from {1} to {2}" -f $cred.resourceRef, $cred.properties.value, $updatedRestCertificate.PfxData.EndEntityCertificates.Thumbprint | Trace-Output
                $cred.properties.value = $updatedRestCertificate.PfxData.EndEntityCertificates.Thumbprint
                $credBody = $cred | ConvertTo-Json -Depth 100

                [System.String]$uri = Get-SdnApiEndpoint -NcUri $sdnFabricDetails.NcUrl -ResourceRef $cred.resourceRef
                $null = Invoke-WebRequestWithRetry -Method 'Put' -Uri $uri -Credential $NcRestCredential `
                -Headers $headers -ContentType $content -Body $credBody -UseBasicParsing

                while ($true) {
                    if ($stopWatch.Elapsed.TotalMinutes -ge $timeoutInMinutes) {
                        $stopWatch.Stop()
                        throw New-Object System.TimeoutException("Update of $($cred.resourceRef) did not complete within the alloted time")
                    }

                    $result = Invoke-WebRequestWithRetry -Method 'Get' -Uri $uri -Credential $NcRestCredential
                    switch ($result.Status) {
                        'Updating' {
                            "Status: {0}" -f $result.Status | Trace-Output
                            Start-Sleep -Seconds 5
                        }
                        'Failed' {
                            $stopWatch.Stop()
                            throw New-Object System.Exception("Failed to update $($cred.resourceRef)")
                        }
                        'Succeeded' {
                            "Successfully updated {0}" -f $cred.resourceRef | Trace-Output
                            break
                        }
                    }
                }
            }

            $stopWatch.Stop()
        }

        "Certificate rotation completed successfully" | Trace-Output
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
