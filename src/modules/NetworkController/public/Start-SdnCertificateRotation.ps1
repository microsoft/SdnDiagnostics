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

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true)]
        [System.IO.DirectoryInfo]$CertPath,

        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$CertPassword,

        [Parameter(Mandatory = $false)]
        [Switch]$GenerateCertificate
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
            $restCertSubject = (Get-SdnNetworkControllerRestCertificate).Subject
            $null = New-SdnCertificate -Subject $restCertSubject -NotAfter (Get-Date).AddDays(365)

            # generate NC node certificates
            foreach ($controller in $sdnFabricDetails.NetworkController) {
                Invoke-PSRemoteCommand -ComputerName $controller -Credential $Credential -ScriptBlock {
                    $nodeCertSubject = (Get-SdnNetworkControllerNodeCertificate).Subject
                    $null = New-SdnCertificate -Subject $nodeCertSubject -NotAfter (Get-Date).AddDays(365)
                }
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

                # if self signed was defined, then we need to export the public key from the certificate and import into Cert:\LocalMachine\Root
                if ($using:SelfSigned) {
                    $filePath = "$($using:certDir)\NC_Rest.cer"
                    $null = Export-Certificate -Type CERT -FilePath $filePath -Cert $pfxCertificate
                    $null = Import-Certificate -FilePath $filePath -CertStoreLocation "Cert:\LocalMachine\Root"
                }
            } -ErrorAction Stop
        }

        # if $SelfSigned, we need to take a copy of the REST certificate .cer file we exported
        # in previous steps, and install a copy on the servers and muxes for southbound communication
        if ($restCertificateSelfSigned) {
            "[{0}]: Importing the public key of the certificate to root store" -f $node | Trace-Output
            Copy-FileFromRemoteComputer -ComputerName $sdnFabricDetails.NetworkController[0] -Credential $Credential -Path "$certDir\NC_Rest.cer" -Destination $certDir
            foreach ($node in $southBoundNodes) {
                Copy-FileToRemoteComputer -ComputerName $node -Credential $Credential -Path "$certDir\NC_Rest.cer" -Destination "$certDir\NC_Rest.cer"

                "[{0}]: Importing certificate {1}" -f $node, $("$certDir\$node.cer") | Trace-Output
                Invoke-PSRemoteCommand -ComputerName $node -Credential $Credential -ScriptBlock {
                    $null = Import-Certificate -FilePath "$($using:certDir)\NC_Rest.cer" -CertStoreLocation "Cert:\LocalMachine\Root"
                } -ErrorAction Stop
            }
        }

        # install the node certificates
        foreach ($node in $sdnFabricDetails.NetworkController) {
            $nodeCertConfig = $certificateConfig.NetworkController[$node]
            Copy-FileToRemoteComputer -ComputerName $node -Credential $Credential -Path $nodeCertConfig.UpdatedCert.FileInfo.FullName -Destination $certDir

            "[{0}]: Importing {1}" -f $node, $nodeCertConfig.UpdatedCert.PfxData.EndEntityCertificates.Thumbprint | Trace-Output
            Invoke-PSRemoteCommand -ComputerName $node -Credential $Credential -ScriptBlock {
                $pfxCertToInstall = Get-ChildItem -Path $using:certDir | Where-Object {$_.Name -ieq $using:nodeCertConfig.UpdatedCert.FileInfo.Name}
                $pfxCertificate = Import-PfxCertificate -FilePath $pfxCertToInstall.FullName -CertStoreLocation 'Cert:\LocalMachine\My' -Password $using:CertPassword -Exportable -ErrorAction Stop

                Set-SdnCertificateAcl -Path 'Cert:\LocalMachine\My' -Thumbprint $pfxCertificate.Thumbprint

                # if self signed was defined, then we need to export the public key from the certificate and import into Cert:\LocalMachine\Root
                if ($using:SelfSigned) {
                    $filePath = "$($using:certDir)\$($using:node).cer"
                    $null = Export-Certificate -Type CERT -FilePath $filePath -Cert $pfxCertificate
                    $null = Import-Certificate -FilePath $filePath -CertStoreLocation "Cert:\LocalMachine\Root"
                }
            } -ErrorAction Stop

            # if self signed was defined, we need to take a copy of the .cer file we exported
            # to copy to the other network controller VMs
            if ($nodeCertConfig.UpdatedCert.SelfSigned) {
                "[{0}]: Importing the public key of the certificate to root store" -f $node | Trace-Output

                # if we are not currently seeding the certificate to current node
                # then we will want to copy the *.cer file from the remote node and bring to the local workstation
                if (-NOT (Test-ComputerNameIsLocal -ComputerName $node)) {
                    Copy-FileFromRemoteComputer -ComputerName $node -Credential $Credential -Path "$certDir\*.cer" -Destination $certDir
                }

                foreach ($controller in ($sdnFabricDetails.NetworkController)) {
                    if (-NOT (Test-ComputerNameIsLocal -ComputerName $controller)) {
                        Copy-FileToRemoteComputer -ComputerName $controller -Credential $Credential -Path "$certDir\$node.cer" -Destination "$certDir\$node.cer"
                    }

                    "[{0}]: Importing certificate {1}" -f $controller, "$node.cer" | Trace-Output
                    Invoke-PSRemoteCommand -ComputerName $controller -Credential $Credential -ScriptBlock {
                        $null = Import-Certificate -FilePath "$($using:certDir)\$($using:node).cer" -CertStoreLocation "Cert:\LocalMachine\Root"
                    } -ErrorAction Stop
                }
            }
        }

        #####################################
        #
        # Rotate NC Northbound Certificate (REST)
        #
        #####################################

        $timeoutInMinutes = 30
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

        "== STAGE: ROTATE NC REST CERTIFICATE ==" | Trace-Output
        "Updating NC REST API to use certificate thumbprint {0}" -f $updatedRestCertificate.PfxData.EndEntityCertificates.Thumbprint | Trace-Output

        try {
            $cert = Get-ChildItem -Path 'Cert:\LocalMachine\My' | Where-Object {$_.Thumbprint -ieq $updatedRestCertificate.PfxData.EndEntityCertificates.Thumbprint}
            if ($cert) {
                Set-Networkcontroller -ServerCertificate $cert
            }
            else {
                throw New-Object System.NullReferenceException("Unable to locate rest certificate")
            }
        }
        catch [InvalidOperationException] {
            if ($_.FullyQualifiedErrorId -ilike "*UpdateInProgress*") {
                "Networkcontroller is being updated by another operation.`n`t{0}" -f $fullyQualifiedErrorId | Trace-Output -Level:Warning
            }
            else {
                $stopWatch.Stop()
                throw $_
            }
        }

        while ($true) {
            if ($stopWatch.Elapsed.TotalMinutes -ge $timeoutInMinutes) {
                throw New-Object System.TimeoutException("Rotate of NC rest certificate did not complete within the alloted time")
            }

            $result = Get-Networkcontroller
            if ($result.ServerCertificate.Thumbprint -ieq $updatedRestCertificate.PfxData.EndEntityCertificates.Thumbprint) {
                "Successfully rotated the NC rest certificate" | Trace-Output
                break
            }
            else {
                "Thumbprint for NC currently set to {0}. Expected {1}. Waiting... {2} seconds" -f `
                $result.ServerCertificate.Thumbprint, $updatedRestCertificate.PfxData.EndEntityCertificates.Thumbprint, $stopWatch.Elapsed.TotalSeconds | Trace-Output
                Start-Sleep -Seconds 15
            }
        }

        $stopWatch.Stop()

        #####################################
        #
        # Rotate Cluster Certificate
        #
        #####################################

        $timeoutInMinutes = 30
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

        "== STAGE: ROTATE NC CLUSTER CERTIFICATE ==" | Trace-Output

        "Updating NC cluster to use certificate thumbprint {0}" -f $updatedRestCertificate.PfxData.EndEntityCertificates.Thumbprint | Trace-Output
        try {
            $cert = Get-ChildItem -Path 'Cert:\LocalMachine\My' | Where-Object {$_.Thumbprint -ieq $updatedRestCertificate.PfxData.EndEntityCertificates.Thumbprint}
            if ($cert){
                Set-NetworkControllerCluster -CredentialEncryptionCertificate $cert
            }
            else {
                throw New-Object System.NullReferenceException("Unable to locate rest certificate")
            }
        }
        catch [InvalidOperationException] {
            if ($_.FullyQualifiedErrorId -ilike "*UpdateInProgress*") {
                "Networkcontroller is being updated by another operation.`n`t{0}" -f $fullyQualifiedErrorId | Trace-Output -Level:Warning
            }
            else {
                $stopWatch.Stop()
                throw $_
            }
        }

        while ($true) {
            if ($stopWatch.Elapsed.TotalMinutes -ge $timeoutInMinutes) {
                throw New-Object System.TimeoutException("Rotate of NC cluster certificate did not complete within the alloted time")
            }

            $result = Get-NetworkControllerCluster
            if ($result.CredentialEncryptionCertificate.Thumbprint -ieq $updatedRestCertificate.PfxData.EndEntityCertificates.Thumbprint) {
                "Successfully rotated the NC cluster certificate" | Trace-Output
                break
            }
            else {
                "Thumbprint for NC Cluster currently set to {0}. Expected {1}. Waiting... {2} seconds" -f `
                $result.CredentialEncryptionCertificate.Thumbprint, $updatedRestCertificate.PfxData.EndEntityCertificates.Thumbprint, $stopWatch.Elapsed.TotalSeconds | Trace-Output
                Start-Sleep -Seconds 15
            }
        }

        $stopWatch.Stop()

        #####################################
        #
        # Rotate NC Node Certificates
        #
        #####################################

        $timeoutInMinutes = 30

        "== STAGE: ROTATE NC NODE CERTIFICATE ==" | Trace-Output

        foreach ($node in $sdnFabricDetails.NetworkController){
            "Updating {0} to use node certificate thumbprint {1}" -f $node, $nodeCertConfig.UpdatedCert.PfxData.EndEntityCertificates.Thumbprint | Trace-Output
            $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
            $nodeCertConfig = $certificateConfig.NetworkController[$node]

            try {
                if (Test-ComputerNameIsLocal -ComputerName $node) {
                    $cert = Get-ChildItem -Path 'Cert:\LocalMachine\My' | Where-Object {$_.Thumbprint -ieq $nodeCertConfig.UpdatedCert.PfxData.EndEntityCertificates.Thumbprint}
                    Set-NetworkControllerNode -Name $node -NodeCertificate $cert
                }
                else {
                    $remoteCert = Invoke-PSRemoteCommand -ComputerName $node -Credential $Credential -ScriptBlock {
                        Get-ChildItem -Path 'Cert:\LocalMachine\My' | Where-Object {$_.Thumbprint -ieq $using:nodeCertConfig.UpdatedCert.PfxData.EndEntityCertificates.Thumbprint}
                    }
                    if ($remoteCert) {
                        Set-NetworkControllerNode -Name $node -ComputerName $node -NodeCertificate $remoteCert
                    }
                    else {
                        "Unable to locate certificate {0} on {1}" -f $nodeCertConfig.UpdatedCert.PfxData.EndEntityCertificates.Thumbprint, $node | Trace-Output -Level:Exception
                    }
                }
            }
            catch [InvalidOperationException] {
                $stopWatch.Stop()
                throw $_
            }

            while ($true) {
                if ($stopWatch.Elapsed.TotalMinutes -ge $timeoutInMinutes) {
                    throw New-Object System.TimeoutException("Rotate of NC cluster certificate did not complete within the alloted time")
                }

                $result = Invoke-PSRemoteCommand -ComputerName $node -Credential $Credential -ScriptBlock {
                    Get-SdnNetworkControllerNodeCertificate
                }

                if ($result.NodeCertificate.Thumbprint -ieq $nodeCertConfig.UpdatedCert.PfxData.EndEntityCertificates.Thumbprint) {
                    break
                }
                else {
                    "Thumbprint for {0} currently set to {1}. Expected {2}. Waiting... {3} seconds" -f `
                    $node, $result.NodeCertificate.Thumbprint, $nodeCertConfig.UpdatedCert.PfxData.EndEntityCertificates.Thumbprint, $stopWatch.Elapsed.TotalSeconds | Trace-Output
                    Start-Sleep -Seconds 15
                }
            }

            $stopWatch.Stop()
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

        $allCredentials = Get-SdnResource -ResourceType Credentials -Credential $NcRestCredential
        foreach ($cred in $allCredentials) {
            $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

            if ($cred.properties.type -eq "X509Certificate") {
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
