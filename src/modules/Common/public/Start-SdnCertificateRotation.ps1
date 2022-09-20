# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Start-SdnCertificateRotation {
    <#
    .SYNOPSIS
        Performs a controller certificate rotate operation for Network Controller Northbound API, Southbound communications and Network Controller nodes.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operate
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$NetworkController,

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
        [Switch]$SelfSigned
    )

    try {
        "Starting certificate rotation" | Trace-Output
        "Retrieving current SDN environment details" | Trace-Output

        # determine fabric information and current version settings for network controller
        $sdnFabricDetails = Get-SdnInfrastructureInfo -NetworkController $NetworkController -Credential $Credential -NcRestCredential $NcRestCredential
        $ncSettings = Invoke-PSRemoteCommand -ComputerName $NetworkController -Credential $Credential -ScriptBlock {
            return [PSCustomObject]@{
                NetworkControllerVersion        = (Get-NetworkController).Version
                NetworkControllerClusterVersion = (Get-NetworkControllerCluster).Version
            }
        }

        "Network Controller version: {0}" -f $ncSettings.NetworkControllerVersion | Trace-Output
        "Network Controller cluster version: {0}" -f $ncSettings.NetworkControllerClusterVersion | Trace-Output

        #####################################
        #
        # Certificate Configuration
        #
        #####################################

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
            $object = [PSCustomObject]@{
                FileInfo = $pfxFile
                PfxData = $pfxData
            }

            $certificateCache += $object
        }

        # enumerate the NC REST certificates
        "Retrieving Rest Certificate" | Trace-Output
        $currentRestCertificate = Invoke-PSRemoteCommand -ComputerName $NetworkController -Credential $Credential -ScriptBlock { Get-SdnNetworkControllerRestCertificate } -ErrorAction Stop
        if ($currentRestCertificate.NotAfter -le (Get-Date)) {
            $certIsExpired = $true
            "[Thumbprint: {0}] NC REST certificate is expired" -f $currentRestCertificate.Thumbprint | Trace-Output -Level:Warning
        }

        foreach ($cert in $certificateCache) {
            if ($cert.PfxData.EndEntityCertificates.Subject -ieq $currentRestCertificate.Subject) {
                $updatedRestCertificate = $cert
                "Matched {0} to NC Rest Certificate" -f $cert.FileInfo.FullName | Trace-Output
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
                    "Matched {0} to {1}" -f $updatedNodeCert.FileInfo.Name, $node | Trace-Output

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
        # there is more advanced remediation steps required to unblock
        # this scenario that this function does not handle currently
        if ($certIsExpired) {
            throw New-Object System.NotSupportedException("Network Controller certificates are expired")
        }

        #####################################
        #
        # Certificate Seeding
        #
        #####################################

        [System.String]$certDir = "$(Get-WorkingDirectory)\RotateCerts"

        $nodesToRotate = @()
        $nodesToRotate += $sdnFabricDetails.NetworkController
        $nodesToRotate += $sdnFabricDetails.Server
        $nodesToRotate += $sdnFabricDetails.SoftwareLoadBalancer

        $southBoundNodes = @()
        $southBoundNodes += $sdnFabricDetails.Server
        $southBoundNodes += $sdnFabricDetails.SoftwareLoadBalancer

        "Creating {0} directory for certifcate staging on {1}" -f $certDir, ($nodesToRotate -join ', ') | Trace-Output
        Invoke-PSRemoteCommand -ComputerName $nodesToRotate -ScriptBlock {
            # create the directories if does not already exist
            if (-NOT (Test-Path -Path $using:certDir -PathType Container)) {
                $null = New-Item -Path $using:certDir -ItemType Directory -Force
            }
        }

        # install the rest certificate
        foreach ($node in $sdnFabricDetails.NetworkController) {
            Copy-FileToRemoteComputer -ComputerName $node -Credential $Credential -Path $updatedRestCertificate.FileInfo.FullName -Destination $certDir

            "Importing {0} on {1}" -f $updatedRestCertificate.PfxData.EndEntityCertificates.Thumbprint, $node | Trace-Output
            Invoke-PSRemoteCommand -ComputerName $node -Credential $Credential -ScriptBlock {
                $pfxCertToInstall = Get-ChildItem -Path $using:certDir | Where-Object {$_.Name -ieq $using:updatedRestCertificate.FileInfo.Name}
                $pfxCertificate = Import-PfxCertificate -FilePath $pfxCertToInstall.FullName -CertStoreLocation 'Cert:\LocalMachine\My' -Password $using:CertPassword -Exportable -ErrorAction Stop

                Set-SdnNetworkControllerCertificateAcl -Path 'Cert:\LocalMachine\My' -Thumbprint $($pfxCertificate.Thumbprint).ToString()

                # if self signed was defined, then we need to export the public key from the certificate and import into Cert:\LocalMachine\Root
                if ($using:SelfSigned) {
                    $filePath = "$($using:certDir)\NC_Rest.cer"
                    $null = Export-Certificate -Type CERT -FilePath $filePath -Cert $pfxCertificate
                    $null = Import-Certificate -FilePath $filePath -CertStoreLocation "Cert:\LocalMachine\Root"
                }
            }
        }

        # if $SelfSigned, we need to take a copy of the REST certificate .cer file we exported
        # in previous steps, and install a copy on the servers and muxes for southbound communication
        if ($SelfSigned) {
            "SelfSigned was declared. Importing the public key of the certificates to root store" | Trace-Output
            Copy-FileFromRemoteComputer -ComputerName $sdnFabricDetails.NetworkController[0] -Credential $Credential -Path "$certDir\NC_Rest.cer" -Destination $certDir
            foreach ($node in $southBoundNodes) {
                Copy-FileToRemoteComputer -ComputerName $node -Credential $Credential -Path "$certDir\NC_Rest.cer" -Destination "$certDir\NC_Rest.cer"

                "Importing certificate {0} on {1}" -f $("$certDir\$node.cer"), $node | Trace-Output
                Invoke-PSRemoteCommand -ComputerName $node -Credential $Credential -ScriptBlock {
                    $null = Import-Certificate -FilePath "$($using:certDir)\NC_Rest.cer" -CertStoreLocation "Cert:\LocalMachine\Root"
                }
            }
        }

        # install the node certificates
        foreach ($node in $sdnFabricDetails.NetworkController) {
            $nodeCertConfig = $certificateConfig.NetworkController[$node]
            Copy-FileToRemoteComputer -ComputerName $node -Credential $Credential -Path $nodeCertConfig.UpdatedCert.FileInfo.FullName -Destination $certDir

            "Importing {0} on {1}" -f $nodeCertConfig.UpdatedCert.PfxData.EndEntityCertificates.Thumbprint, $node | Trace-Output
            Invoke-PSRemoteCommand -ComputerName $node -Credential $Credential -ScriptBlock {
                $pfxCertToInstall = Get-ChildItem -Path $using:certDir | Where-Object {$_.Name -ieq $using:nodeCertConfig.UpdatedCert.FileInfo.Name}
                $pfxCertificate = Import-PfxCertificate -FilePath $pfxCertToInstall.FullName -CertStoreLocation 'Cert:\LocalMachine\My' -Password $using:CertPassword -Exportable -ErrorAction Stop

                Set-SdnNetworkControllerCertificateAcl -Path 'Cert:\LocalMachine\My' -Thumbprint $pfxCertificate.Thumbprint

                # if self signed was defined, then we need to export the public key from the certificate and import into Cert:\LocalMachine\Root
                if ($using:SelfSigned) {
                    $filePath = "$($using:certDir)\$($using:node).cer"
                    $null = Export-Certificate -Type CERT -FilePath $filePath -Cert $pfxCertificate
                    $null = Import-Certificate -FilePath $filePath -CertStoreLocation "Cert:\LocalMachine\Root"
                }
            }

            # if self signed was defined, we need to take a copy of the .cer file we exported
            # to copy to the other network controller VMs
            if ($SelfSigned) {
                "SelfSigned was declared. Importing the public key of the certificates to root store" | Trace-Output

                Copy-FileFromRemoteComputer -ComputerName $node -Credential $Credential -Path "$certDir\*.cer" -Destination $certDir
                foreach ($controller in ($sdnFabricDetails.NetworkController | Where-Object {$_ -ne $node})) {
                    Copy-FileToRemoteComputer -ComputerName $controller -Credential $Credential -Path "$certDir\$node.cer" -Destination "$certDir\$node.cer"

                    "Importing certificate {0} on {1}" -f $("$certDir\$node.cer"), $node | Trace-Output
                    Invoke-PSRemoteCommand -ComputerName $controller -Credential $Credential -ScriptBlock {
                        $null = Import-Certificate -FilePath "$($using:certDir)\$($using:node).cer" -CertStoreLocation "Cert:\LocalMachine\Root"
                    }
                }
            }
        }

        <#
        #####################################
        #
        # Rotate NC Northbound Certificate (REST)
        #
        #####################################

        $timeoutInMinutes = 10
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

        "Rotating the NC REST certificate" | Trace-Output
        try {
            Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock {
                $cert = Get-SdnCertificate -Thumbprint $using:updatedRestCertificate.PfxData.EndEntityCertificates.Thumbprint
                if ($cert) {
                    Set-Networkcontroller -ServerCertificate $cert
                }
            } -Credential $Credential
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

            $result = Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock {
                Get-Networkcontroller
            } -Credential $Credential

            if ($result.ServerCertificate.Thumbprint -ieq $updatedRestCertificate.Thumbprint) {
                "Successfully rotated the NC rest certificate" | Trace-Output
                break
            }
            else {
                "Waiting... {0} seconds" -f $stopWatch.Elapsed.TotalSeconds | Trace-Output
                Start-Sleep -Seconds 10
            }
        }

        $stopWatch.Stop()

        #####################################
        #
        # Rotate Cluster Certificate
        #
        #####################################

        $timeoutInMinutes = 10
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

        "Rotating the NC cluster certificate" | Trace-Output

        try {
            Invoke-PSRemoteCommand -ComputerName $NetworkController -Credential $Credential -ScriptBlock {
                $cert = Get-SdnCertificate -Thumbprint $using:updatedRestCertificate.PfxData.EndEntityCertificates.Thumbprint
                if ($cert){
                    Set-NetworkControllerCluster -CredentialEncryptionCertificate $cert
                }
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

            $result = Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock {
                Get-NetworkControllerCluster
            } -Credential $Credential

            if ($result.CredentialEncryptionCertificate.Thumbprint -ieq $newRestCertificate.Thumbprint) {
                break
            }
            else {
                "Waiting... {0} seconds" -f $stopWatch.Elapsed.TotalSeconds | Trace-Output
                Start-Sleep -Seconds 10
            }
        }

        $stopWatch.Stop()

        #####################################
        #
        # Rotate NC Node Certificates
        #
        #####################################

        foreach ($node in $sdnFabricDetails.NetworkController){
            "Rotating the NC Node certificate for {0}" -f $node | Trace-Output
            $timeoutInMinutes = 10
            $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
            $nodeCertConfig = $certificateConfig.NetworkController[$node]

            try {
                Invoke-PSRemoteCommand -ComputerName $node -Credential $Credential -ScriptBlock {
                    $cert = Get-SdnCertificate -Thumbprint $using:nodeCertConfig.UpdatedCert.PfxData.EndEntityCertificates.Thumbprint
                    Set-NetworkControllerNode -Name $env:COMPUTERNAME -NodeCertificate $cert
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

                if ($result.NodeCertificate.Thumbprint -ieq $updatedRestCertificate.Thumbprint) {
                    break
                }
                else {
                    "Expected and actual certificate thumbprint do not match. Waiting and will retry..." | Trace-Output
                    Start-Sleep -Seconds 10
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

        "Updating the southbound certificate credentials" | Trace-Output
        $allCredentials = Get-SdnResource -ResourceType Credentials -Credential $NcRestCredential
        foreach ($cred in $allCredentials) {
            $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

            if ($cred.properties.type -eq "X509Certificate") {
                "{0} will be updated from {1} to {2}" -f $cred.resourceRef, $cred.properties.value, $newRestCertificate.Thumbprint | Trace-Output
                $cred.properties.value = $newRestCertificate.Thumbprint
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
        #>
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
