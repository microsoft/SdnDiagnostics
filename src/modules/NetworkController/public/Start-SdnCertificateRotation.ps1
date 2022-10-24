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
        $ncClusterSettings = Get-NetworkControllerCluster
        $ncSettings = @{
            NetworkControllerVersion        = (Get-NetworkController).Version
            NetworkControllerClusterVersion = $ncClusterSettings.Version
            ClusterAuthentication = $ncClusterSettings.ClusterAuthentication
        }

        $currentRestCert = Get-SdnNetworkControllerRestCertificate

        if ($ncSettings.ClusterAuthentication -ieq 'X509') {
            $rotateNCNodeCerts = $true
        }

        # before we proceed with anything else, we want to make sure that all the Network Controllers within the SDN fabric are running the current version
        Install-SdnDiagnostics -ComputerName $sdnFabricDetails.NetworkController -ErrorAction Stop
        Install-SdnDiagnostics -ComputerName $sdnFabricDetails.SoftwareLoadBalancer -ErrorAction Stop
        Install-SdnDiagnostics -ComputerName $sdnFabricDetails.Server -ErrorAction Stop

        "Network Controller version: {0}" -f $ncSettings.NetworkControllerVersion | Trace-Output
        "Network Controller cluster version: {0}" -f $ncSettings.NetworkControllerClusterVersion | Trace-Output

        $healthState = Get-SdnServiceFabricClusterHealth -NetworkController $env:COMPUTERNAME
        if ($healthState.AggregatedHealthState -ine 'Ok') {
            "Service Fabric AggregatedHealthState is currently reporting {0}. Please address underlying health before proceeding with certificate rotation" `
            -f $healthState.AggregatedHealthState | Trace-Output -Level:Exception

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

            $restCert = New-SdnCertificate -Subject $currentRestCert.Subject -NotAfter (Get-Date).AddDays(365)

            # after the certificate has been generated, we want to export the certificate using the $CertPassword provided by the operator
            # and save the file to directory. This allows the rest of the function to pick up these files and perform the steps as normal
            [System.String]$filePath = "$(Join-Path -Path $CertPath.FullName -ChildPath $currentRestCert.Subject.ToString().ToLower().Replace('.','_').Replace('=','_').Trim()).pfx"
            "Exporting pfx certificate to {0}" -f $filePath | Trace-Output
            $null = Export-PfxCertificate -Cert $restCert -FilePath $filePath -Password $CertPassword -CryptoAlgorithmOption AES256_SHA256

            # generate NC node certificates
            if ($rotateNCNodeCerts) {
                "ClusterAuthentication is currently configured for {0}. Creating node certificates" -f $ncSettings.ClusterAuthentication | Trace-Output
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
        }

        #####################################
        #
        # Certificate Seeding
        #
        #####################################

        if ($PSBoundParameters.ContainsKey('GenerateCertificate') -or $PSBoundParameters.ContainsKey('CertPath')) {
            "== STAGE: CERTIFICATE SEEDING ==" | Trace-Output
            Copy-CertificatesToFabric -CertPath $CertPath.FullName -CertPassword $CertPassword -FabricDetails $sdnFabricDetails -RotateNodeCertificates:$rotateNCNodeCerts
        }

        #####################################
        #
        # Certificate Configuration
        #
        #####################################

        "== STAGE: DETERMINE CERTIFICATE CONFIG ==" | Trace-Output

        $certificateConfig = @{
            RestCert = $null
            NetworkController = @{}
        }

        $updatedRestCertificate = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -ieq $currentRestCert.Subject} `
        | Sort-Object -Property NotBefore -Descending | Select-Object -First 1
        if ($updatedRestCertificate) {
            $certificateConfig.RestCert = $updatedRestCertificate
        }

        if ($rotateNCNodeCerts) {
            foreach ($controller in $sdnFabricDetails.NetworkController) {

                $currentNodeCert = Invoke-PSRemoteCommand -ComputerName $controller -Credential $Credential -ScriptBlock {
                    Get-SdnNetworkControllerNodeCertificate
                }

                $updatedNodeCert = Invoke-PSRemoteCommand -ComputerName $controller -Credential $Credential -ScriptBlock {
                    Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -ieq $using:currentNodeCert.Subject} `
                    | Sort-Object -Property NotBefore -Descending | Select-Object -First 1
                }

                $certificateConfig.NetworkController[$controller] = [PSCustomObject]@{
                    New = $updatedNodeCert
                    Current =  $currentNodeCert
                }
            }
        }

        $certificateConfig | Export-ObjectToFile -FilePath (Get-WorkingDirectory) -Name 'Rotate_Certificate_Config' -FileType 'json'

        "Network Controller Rest Certificate {0} will be updated from [Thumbprint:{1} NotAfter:{2}] to [Thumbprint:{3} NotAfter:{4}]" `
        -f $currentRestCert.Subject, $currentRestCert.Thumbprint, $currentRestCert.NotAfter, $certificateConfig.RestCert.Thumbprint, $certificateConfig.RestCert.NotAfter `
        | Trace-Output -Level:Warning

        foreach ($node in $sdnFabricDetails.NetworkController) {
            $nodeCertConfig = $certificateConfig.NetworkController[$node]
            "Network Controller Node Certificate {0} will be updated from [Thumbprint:{1} NotAfter:{2}] to [Thumbprint:{3} NotAfter:{4}]" `
            -f $nodeCertConfig.Current.Subject, $nodeCertConfig.Current.Thumbprint, $nodeCertConfig.Current.NotAfter, `
            $nodeCertConfig.New.Thumbprint, $nodeCertConfig.New.NotAfter | Trace-Output -Level:Warning
        }

        $confirm = Confirm-UserInput
        if (-NOT $confirm){
            "User has opted to abort the operation. Terminating operation" | Trace-Output -Level:Warning
            return
        }

        #####################################
        #
        # Rotate NC Northbound Certificate (REST)
        #
        #####################################

        "== STAGE: ROTATE NC REST CERTIFICATE ==" | Trace-Output

        $null = Invoke-CertRotateCommand -Command 'Set-NetworkController' -Credential $Credential -Thumbprint ($certificateConfig.RestCert.Thumbprint).ToString()

        "Waiting for 5 minutes before proceeding to the next step. Script will resume at {0}" -f (Get-Date).AddMinutes(5).ToUniversalTime().ToString() | Trace-Output
        Start-Sleep -Seconds 300

        #####################################
        #
        # Rotate Cluster Certificate
        #
        #####################################

        "== STAGE: ROTATE NC CLUSTER CERTIFICATE ==" | Trace-Output

        $null = Invoke-CertRotateCommand -Command 'Set-NetworkControllerCluster' -Credential $Credential -Thumbprint ($certificateConfig.RestCert.Thumbprint).ToString()

        "Waiting for 5 minutes before proceeding to the next step. Script will resume at {0}" -f (Get-Date).AddMinutes(5).ToUniversalTime().ToString() | Trace-Output
        Start-Sleep -Seconds 300

        #####################################
        #
        # Rotate NC Node Certificates
        #
        #####################################

        if ($ncSettings.ClusterAuthentication -ieq 'X509') {
            "== STAGE: ROTATE NC NODE CERTIFICATE ==" | Trace-Output

            foreach ($node in $sdnFabricDetails.NetworkController){
                $nodeCertConfig = $certificateConfig.NetworkController[$node]
                $null = Invoke-CertRotateCommand -Command 'Set-NetworkControllerNode' -NetworkController $node -Credential $Credential -Thumbprint ($nodeCertConfig.New.Thumbprint).ToString()

                "Waiting for 2 minutes before proceeding to the next step. Script will resume at {0}" -f (Get-Date).AddMinutes(5).ToUniversalTime().ToString() | Trace-Output
                Start-Sleep -Seconds 120
            }
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
                if ($cred.properties.value -ieq $certificateConfig.RestCert.Thumbprint) {
                    "{0} has already been configured to {1}" -f $cred.resourceRef, $certificateConfig.RestCert.Thumbprint | Trace-Output
                    continue
                }

                "{0} will be updated from {1} to {2}" -f $cred.resourceRef, $cred.properties.value, $certificateConfig.RestCert.Thumbprint | Trace-Output
                $cred.properties.value = $certificateConfig.RestCert.Thumbprint
                $credBody = $cred | ConvertTo-Json -Depth 100

                [System.String]$uri = Get-SdnApiEndpoint -NcUri $sdnFabricDetails.NcUrl -ResourceRef $cred.resourceRef
                $null = Invoke-WebRequestWithRetry -Method 'Put' -Uri $uri -Credential $NcRestCredential -UseBasicParsing `
                -Headers $headers -ContentType $content -Body $credBody

                while ($true) {
                    if ($stopWatch.Elapsed.TotalMinutes -ge $timeoutInMinutes) {
                        $stopWatch.Stop()
                        throw New-Object System.TimeoutException("Update of $($cred.resourceRef) did not complete within the alloted time")
                    }

                    $result = Invoke-WebRequestWithRetry -Method 'Get' -Uri $uri -Credential $NcRestCredential -UseBasicParsing
                    switch ($result.Status) {
                        'Updating' {
                            "Status: {0}" -f $result.Status | Trace-Output
                            Start-Sleep -Seconds 15
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
