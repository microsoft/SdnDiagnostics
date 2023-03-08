function Start-SdnCertificateRotation {
    <#
    .SYNOPSIS
        Performs a controller certificate rotate operation for Network Controller Northbound API, Southbound communications and Network Controller nodes.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    .PARAMETER CertPath
        Path directory where certificate(s) .pfx files are located for use with certificate rotation.
    .PARAMETER GenerateCertificate
        Switch to determine if certificate rotate function should generate self-signed certificates.
    .PARAMETER CertPassword
        SecureString password for accessing the .pfx files, or if using -GenerateCertificate, what the .pfx files will be encrypted with.
    .PARAMETER NotAfter
        Expiration date when using -GenerateCertificate. If ommited, defaults to 3 years.
    .PARAMETER CertRotateConfig
        The Config generated by New-SdnCertificateRotationConfig to include NC REST certificate thumbprint and node certificate thumbprint.
    .PARAMETER Force
        Switch to force the rotation without being prompted, when Service Fabric is unhealthy.
    #>

    [CmdletBinding(DefaultParameterSetName = 'GenerateCertificate')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $true, ParameterSetName = 'GenerateCertificate')]
        [Parameter(Mandatory = $true, ParameterSetName = 'CertConfig')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Parameter(Mandatory = $false, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $false, ParameterSetName = 'GenerateCertificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'CertConfig')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'Pfx')]
        [System.String]$CertPath,

        [Parameter(Mandatory = $true, ParameterSetName = 'GenerateCertificate')]
        [Switch]$GenerateCertificate,

        [Parameter(Mandatory = $true, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $true, ParameterSetName = 'GenerateCertificate')]
        [System.Security.SecureString]$CertPassword,

        [Parameter(Mandatory = $false, ParameterSetName = 'GenerateCertificate')]
        [datetime]$NotAfter = (Get-Date).AddYears(3),

        [Parameter(Mandatory = $true, ParameterSetName = 'CertConfig')]
        [hashtable]$CertRotateConfig,

        [Parameter(Mandatory = $false, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $false, ParameterSetName = 'GenerateCertificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'CertConfig')]
        [switch]$Force
    )

    # ensure that the module is running as local administrator
    $elevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-NOT $elevated) {
        throw New-Object System.Exception("This function requires elevated permissions. Run PowerShell as an Administrator and import the module again.")
    }

    $config = Get-SdnRoleConfiguration -Role 'NetworkController'
    $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
    if (-NOT ($confirmFeatures)) {
        throw New-Object System.NotSupportedException("The current machine is not a NetworkController, run this on NetworkController.")
    }

    # add disclaimer that this feature is currently under preview
    if (!$Force) {
        "This feature is currently under preview. Please report any issues to https://github.com/microsoft/SdnDiagnostics/issues so we can accurately track any issues and help unblock your cert rotation." | Trace-Output -Level:Warning
        $confirm = Confirm-UserInput -Message "Do you want to proceed with certificate rotation? [Y/N]:"
        if (-NOT $confirm) {
            "User has opted to abort the operation. Terminating operation" | Trace-Output -Level:Warning
            return
        }
    }

    try {
        "Starting certificate rotation" | Trace-Output
        "Retrieving current SDN environment details" | Trace-Output

        if ([String]::IsNullOrEmpty($CertPath)) {
            [System.String]$CertPath = "$(Get-WorkingDirectory)\Cert_{0}" -f (Get-FormattedDateTimeUTC)

            if (-NOT (Test-Path -Path $CertPath -PathType Container)) {
                $null = New-Item -Path $CertPath -ItemType Directory -Force
            }
        }

        [System.IO.FileSystemInfo]$CertPath = Get-Item -Path $CertPath -ErrorAction Stop

        # Get the Network Controller Info Offline (NC Cluster Down case)
        $NcInfraInfo = Get-SdnNetworkControllerInfoOffline -Credential $Credential

        if ($NcInfraInfo.ClusterCredentialType -ieq 'X509') {
            $rotateNCNodeCerts = $true
        }

        # Get the current rest certificate to determine if it is expired scenario or not.
        $currentRestCert = Get-SdnNetworkControllerRestCertificate

        $restCertExpired = (Get-Date) -gt $($currentRestCert.NotAfter)
        $ncHealthy = $true

        if (!$restCertExpired) {
            try {
                $null = Get-NetworkController
            }
            catch {
                $ncHealthy = $false
            }
        }

        if ($restCertExpired -or !$ncHealthy) {
            $postRotateSBRestCert = $true
            if ($restCertExpired) {
                "Network Controller Rest Certificate {0} expired at {1}" -f $currentRestCert.Thumbprint, $currentRestCert.NotAfter | Trace-Output -Level:Warning
            }

            "Network Controller is currently not healthy" | Trace-Output -Level:Warning
            $sdnFabricDetails = [SdnFabricInfrastructure]@{
                NetworkController = $NcInfraInfo.NodeList.IpAddressOrFQDN
            }

            Install-SdnDiagnostics -ComputerName $sdnFabricDetails.NetworkController -Credential $Credential -ErrorAction Stop
        }
        else {
            # determine fabric information and current version settings for network controller
            $sdnFabricDetails = Get-SdnInfrastructureInfo -NetworkController $env:COMPUTERNAME -Credential $Credential -NcRestCredential $NcRestCredential
            $ncClusterSettings = Get-NetworkControllerCluster
            $ncSettings = @{
                NetworkControllerVersion        = (Get-NetworkController).Version
                NetworkControllerClusterVersion = $ncClusterSettings.Version
                ClusterAuthentication           = $ncClusterSettings.ClusterAuthentication
            }

            # before we proceed with anything else, we want to make sure that all the Network Controllers within the SDN fabric are running the current version
            Install-SdnDiagnostics -ComputerName $sdnFabricDetails.NetworkController -ErrorAction Stop

            "Network Controller version: {0}" -f $ncSettings.NetworkControllerVersion | Trace-Output
            "Network Controller cluster version: {0}" -f $ncSettings.NetworkControllerClusterVersion | Trace-Output

            $healthState = Get-SdnServiceFabricClusterHealth -NetworkController $env:COMPUTERNAME
            if ($healthState.AggregatedHealthState -ine 'Ok') {
                "Service Fabric AggregatedHealthState is currently reporting {0}. Please address underlying health before proceeding with certificate rotation" `
                    -f $healthState.AggregatedHealthState | Trace-Output -Level:Exception

                if (!$Force) {
                    $confirm = Confirm-UserInput -Message "Do you want to proceed with certificate rotation? Enter N to abort and address the underlying health. Enter Y to force continue:"
                    if (-NOT $confirm) {
                        "User has opted to abort the operation. Terminating operation" | Trace-Output -Level:Warning
                        return
                    }
                }
            }
        }

        #####################################
        #
        # Create Certificate (Optional)
        #
        #####################################

        if ($PSCmdlet.ParameterSetName -ieq 'GenerateCertificate') {
            "== STAGE: CREATE SELF SIGNED CERTIFICATES ==" | Trace-Output

            $newSelfSignedCert = New-SdnNetworkControllerRestCertificate -RestName $NcInfraInfo.NcRestName.ToString() -NotAfter $NotAfter -Path $CertPath.FullName `
                -CertPassword $CertPassword -Credential $Credential -FabricDetails $sdnFabricDetails
            $selfSignedRestCertFile = $newSelfSignedCert.FileInfo

            if ($rotateNCNodeCerts) {
                $null = Invoke-PSRemoteCommand -ComputerName $sdnFabricDetails.NetworkController -Credential $Credential -ScriptBlock {
                    New-SdnNetworkControllerNodeCertificate -NotAfter $using:NotAfter -CertPassword $using:CertPassword `
                        -Credential $using:Credential -Path $using:CertPath.FullName -FabricDetails $sdnFabricDetails
                }
            }

            $CertRotateConfig = New-SdnCertificateRotationConfig -Credential $Credential
        }

        #####################################
        #
        # PFX Certificates (Optional)
        #
        #####################################

        if ($PSCmdlet.ParameterSetName -ieq 'Pfx') {
            "== STAGE: Install PFX Certificates to Fabric ==" | Trace-Output
            $pfxCertificates = Copy-UserProvidedCertificateToFabric -CertPath $CertPath -CertPassword $CertPassword -FabricDetails $sdnFabricDetails `
            -NetworkControllerHealthy:$ncHealthy -Credential $Credential -RotateNodeCerts:$rotateNCNodeCerts

            $pfxCertificates | ForEach-Object {
                if ($_.CertificateType -ieq 'NetworkControllerRest' ) {
                    if ($_.SelfSigned -ieq $true) {
                        $selfSignedRestCertFile = $_.FileInfo
                    }
                }
            }

            $CertRotateConfig = New-SdnCertificateRotationConfig -Credential $Credential
        }

        #####################################
        #
        # Certificate Configuration
        #
        #####################################

        "== STAGE: DETERMINE CERTIFICATE CONFIG ==" | Trace-Output

        "Validating Certificate Configuration" | Trace-Output
        $certValidated = Test-SdnCertificateRotationConfig -NcNodeList $NcInfraInfo.NodeList -CertRotateConfig $CertRotateConfig -Credential $Credential

        if ($certValidated -ne $true) {
            throw New-Object System.NotSupportedException("Unable to validate certificate configuration")
        }

        $updatedRestCertificate = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -ieq $currentRestCert.Subject } `
        | Sort-Object -Property NotBefore -Descending | Select-Object -First 1

        "Network Controller Rest Certificate {0} will be updated from [Thumbprint:{1} NotAfter:{2}] to [Thumbprint:{3} NotAfter:{4}]" `
            -f $currentRestCert.Subject, $currentRestCert.Thumbprint, $currentRestCert.NotAfter, $CertRotateConfig["NcRestCert"], $updatedRestCertificate.NotAfter `
        | Trace-Output -Level:Warning

        if ($rotateNCNodeCerts) {
            foreach ($node in $NcInfraInfo.NodeList) {
                $nodeCertThumbprint = $certRotateConfig[$node.NodeName.ToLower()]
                $currentNodeCert = Invoke-PSRemoteCommand -ComputerName $node.IpAddressOrFQDN -Credential $Credential -ScriptBlock {
                    Get-SdnNetworkControllerNodeCertificate
                }

                $newNodeCert = Invoke-PSRemoteCommand -ComputerName $node.IpAddressOrFQDN -Credential $Credential -ScriptBlock {
                    Get-SdnCertificate -Path 'Cert:\LocalMachine\My' -Thumbprint $using:nodeCertThumbprint
                }

                "Network Controller Node Certificate {0} will be updated from [Thumbprint:{1} NotAfter:{2}] to [Thumbprint:{3} NotAfter:{4}]" `
                    -f $currentNodeCert.Subject, $currentNodeCert.Thumbprint, $currentNodeCert.NotAfter, `
                    $newNodeCert.Thumbprint, $newNodeCert.NotAfter | Trace-Output -Level:Warning
            }
        }

        if (!$Force) {
            $confirm = Confirm-UserInput
            if (-NOT $confirm) {
                "User has opted to abort the operation. Terminating operation" | Trace-Output -Level:Warning
                return
            }
        }

        #####################################
        #
        # Rotate NC Certificate Expired
        #
        #####################################

        if ($restCertExpired -or !$ncHealthy) {
            # Use this for certificate if either rest cert expired or nc unhealthy, get-networkcontroller failed
            Start-SdnExpiredCertificateRotation -CertRotateConfig $CertRotateConfig -Credential $Credential -NcRestCredential $NcRestCredential
        }

        #####################################
        #
        # Rotate NC Northbound Certificate (REST)
        #
        #####################################

        "== STAGE: ROTATE NC REST CERTIFICATE ==" | Trace-Output

        $null = Invoke-CertRotateCommand -Command 'Set-NetworkController' -Credential $Credential -Thumbprint $CertRotateConfig["NcRestCert"]

        "Waiting for 5 minutes before proceeding to the next step. Script will resume at {0}" -f (Get-Date).AddMinutes(5).ToUniversalTime().ToString() | Trace-Output
        Start-Sleep -Seconds 300

        #####################################
        #
        # Rotate Cluster Certificate
        #
        #####################################

        "== STAGE: ROTATE NC CLUSTER CERTIFICATE ==" | Trace-Output

        $null = Invoke-CertRotateCommand -Command 'Set-NetworkControllerCluster' -Credential $Credential -Thumbprint $CertRotateConfig["NcRestCert"]

        "Waiting for 5 minutes before proceeding to the next step. Script will resume at {0}" -f (Get-Date).AddMinutes(5).ToUniversalTime().ToString() | Trace-Output
        Start-Sleep -Seconds 300

        #####################################
        #
        # Rotate NC Node Certificates
        #
        #####################################

        if ($rotateNCNodeCerts) {
            "== STAGE: ROTATE NC NODE CERTIFICATE ==" | Trace-Output

            foreach ($node in $NcInfraInfo.NodeList) {
                $nodeCertThumbprint = $certRotateConfig[$node.NodeName.ToLower()]
                $null = Invoke-CertRotateCommand -Command 'Set-NetworkControllerNode' -NetworkController $node.IpAddressOrFQDN -Credential $Credential -Thumbprint $nodeCertThumbprint

                "Waiting for 2 minutes before proceeding to the next step. Script will resume at {0}" -f (Get-Date).AddMinutes(5).ToUniversalTime().ToString() | Trace-Output
                Start-Sleep -Seconds 120
            }
        }

        #####################################
        #
        # Rotate NC Southbound Certificates
        #
        #####################################

        "== STAGE: ROTATE SOUTHBOUND CERTIFICATE CREDENTIALS ==" | Trace-Output

        $null = Update-NetworkControllerCredentialResource -NcUri "https://$($NcInfraInfo.NcRestName)" -Credential $NcRestCredential `
            -NewRestCertThumbprint $CertRotateConfig["NcRestCert"] -ErrorAction Stop

        "Certificate rotation completed successfully" | Trace-Output

        #####################################
        #
        # Certificate Seeding (Southbound Nodes)
        #
        #####################################

        # if nc was unhealthy and unable to determine southbound devices in the dataplane earlier
        # we now want to check to see if nc is healthy and if we need to install the rest cert (for self-signed) to southbound devices
        if ($postRotateSBRestCert) {
            if ($selfSignedRestCertFile) {
                $sdnFabricDetails = Get-SdnInfrastructureInfo -Credential $Credential -NcRestCredential $NcRestCredential -Force
                $southBoundNodes = @()
                if ($null -ne $sdnFabricDetails.LoadBalancerMux) {
                    $southBoundNodes += $sdnFabricDetails.LoadBalancerMux
                }
                if ($null -ne $sdnFabricDetails.Server) {
                    $southBoundNodes += $sdnFabricDetails.Server
                }

                if ($southBoundNodes) {
                    "== STAGE: REST SELF-SIGNED CERTIFICATE SEEDING (Southbound Nodes) ==" | Trace-Output

                    # ensure that we have the latest version of sdnDiagnostics module on the southbound devices
                    Install-SdnDiagnostics -ComputerName $southBoundNodes -Credential $Credential -ErrorAction Stop

                    "[REST CERT] Installing self-signed certificate to {0}" -f ($southBoundNodes -join ', ') | Trace-Output
                    [System.String]$remoteFilePath = Join-Path -Path $CertPath.FullName -ChildPath $selfSignedRestCertFile.Name
                    Copy-FileToRemoteComputer -ComputerName $southBoundNodes -Credential $Credential -Path $selfSignedRestCertFile.FullName -Destination $remoteFilePath
                    $null = Invoke-PSRemoteCommand -ComputerName $southBoundNodes -Credential $Credential -ScriptBlock {
                        Import-SdnCertificate -FilePath $using:remoteFilePath -CertStore 'Cert:\LocalMachine\Root'
                    } -ErrorAction Stop
                }
            }
        }

        "Certificate rotation has completed" | Trace-Output
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}