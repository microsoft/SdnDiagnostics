function Start-SdnMuxCertificateRotation {
    <#
    .SYNOPSIS
        Performs a certificate rotation operation for the Load Balancer Muxes.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action on the Load Balancer Mux and Network Controller nodes. The default is the current user.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    .PARAMETER CertPath
        Path directory where certificate(s) .pfx files are located for use with certificate rotation.
    .PARAMETER GenerateCertificate
        Switch to determine if certificate rotate function should generate self-signed certificates.
    .PARAMETER CertPassword
        SecureString password for accessing the .pfx files, or if using -GenerateCertificate, what the .pfx files will be encrypted with.
    .PARAMETER NotAfter
        Expiration date when using -GenerateCertificate. If ommited, defaults to 3 years.
    .PARAMETER CertRotateConfig
        The Config generated by New-SdnCertificateRotationConfig to include appropriate certificate thumbprints for mux nodes.
    .PARAMETER Force
        Switch to force the rotation without being prompted, when Service Fabric is unhealthy.
    #>

    [CmdletBinding(DefaultParameterSetName = 'GenerateCertificate')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $true, ParameterSetName = 'GenerateCertificate')]
        [Parameter(Mandatory = $true, ParameterSetName = 'CertConfig')]
        [System.String]$NetworkController,

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

        [Parameter(Mandatory = $false, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $false, ParameterSetName = 'GenerateCertificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'CertConfig')]
        [X509Certificate]$NcRestCertificate,

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

    # these are not yet supported and will take a bit more time to implement as it touches on core framework for rotate functionality
    # however majority of the environments impacted are using sdnexpress which leverage self-signed certificates.
    if ($CertRotateConfig -or $CertPath) {
        "This feature is not yet supported and is under development. Please use -GenerateCertificate or reference {0} for manual steps." `
        -f  'https://learn.microsoft.com/en-us/azure-stack/hci/manage/update-network-controller-certificates?tabs=manual-renewal' | Trace-Output -Level:Warning
        return
    }

    # ensure that the module is running as local administrator
    $elevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-NOT $elevated) {
        throw New-Object System.Exception("This function requires elevated permissions. Run PowerShell as an Administrator and import the module again.")
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

    $array = @()
    $ncRestParams = @{
        NcUri = $null
    }
    $putRestParams = @{
        Body = $null
        Content = "application/json; charset=UTF-8"
        Headers = @{"Accept"="application/json"}
        Method = 'Put'
        Uri = $null
        UseBasicParsing = $true
    }
    $confirmStateParams = @{
        TimeoutInSec = 600
        UseBasicParsing = $true
    }

    if ($PSBoundParameters.ContainsKey('NcRestCertificate')) {
        $restCredParam = @{ NcRestCertificate = $NcRestCertificate }
        $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
        $putRestParams.Add('Certificate', $NcRestCertificate)
    }
    else {
        $restCredParam = @{ NcRestCredential = $NcRestCredential }
        $ncRestParams.Add('NcRestCredential', $NcRestCredential)
        $putRestParams.Add('Credential', $NcRestCredential)
    }
    $confirmStateParams += $restCredParam

    try {
        "Starting certificate rotation" | Trace-Output
        "Retrieving current SDN environment details" | Trace-Output

        if ([String]::IsNullOrEmpty($CertPath)) {
            [System.String]$CertPath = "$(Get-WorkingDirectory)\MuxCert_{0}" -f (Get-FormattedDateTimeUTC)

            if (-NOT (Test-Path -Path $CertPath -PathType Container)) {
                $null = New-Item -Path $CertPath -ItemType Directory -Force
            }
        }

        [System.IO.FileSystemInfo]$CertPath = Get-Item -Path $CertPath -ErrorAction Stop
        $sdnFabricDetails = Get-SdnInfrastructureInfo -NetworkController $NetworkController -Credential $Credential @restCredParam -ErrorAction Stop
        if ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType -ine 'ServiceFabric') {
            throw New-Object System.NotSupportedException("This function is only supported on Service Fabric clusters.")
        }

        $ncRestParams.NcUri = $sdnFabricDetails.NcUrl
        $loadBalancerMuxes = Get-SdnLoadBalancerMux @ncRestParams -ErrorAction Stop

        # before we proceed with anything else, we want to make sure that all the Network Controllers and MUXes within the SDN fabric are running the current version
        Install-SdnDiagnostics -ComputerName $sdnFabricDetails.NetworkController -ErrorAction Stop
        Install-SdnDiagnostics -ComputerName $sdnFabricDetails.LoadBalancerMux -ErrorAction Stop

        #####################################
        #
        # Create Certificate (Optional)
        #
        #####################################

        if ($PSCmdlet.ParameterSetName -ieq 'GenerateCertificate') {
            "== STAGE: CREATE SELF SIGNED CERTIFICATES ==" | Trace-Output

            # retrieve the corresponding virtualserver reference for each loadbalancermux
            # and invoke remote operation to the mux to generate the self-signed certificate that matches the managementAddress for x509 credentials
            foreach ($muxResource in $loadBalancerMuxes) {
                $virtualServer = Get-SdnResource @ncRestParams -ResourceRef $muxResource.properties.virtualServer.resourceRef
                $virtualServerConnection = $virtualServer.properties.connections | Where-Object { $_.credentialType -ieq "X509Certificate" -or $_.credentialType -ieq "X509CertificateSubjectName" }
                $managementAddress = $virtualServerConnection.managementAddresses[0]

                $muxCert = Invoke-PSRemoteCommand -ComputerName $managementAddress -Credential $Credential -ScriptBlock {
                    param(
                        [Parameter(Position = 0)][DateTime]$param1,
                        [Parameter(Position = 1)][PSCredential]$param2,
                        [Parameter(Position = 2)][String]$param3,
                        [Parameter(Position = 3)][System.Object]$param4
                    )

                    New-SdnMuxCertificate -NotAfter $param1 -Credential $param2 -Path $param3 -FabricDetails $param4
                } -ArgumentList @($NotAfter, $Credential, $CertPath.FullName, $sdnFabricDetails)

                $array += [PSCustomObject]@{
                    ManagementAddress = $managementAddress
                    ResourceRef = $virtualServer.resourceRef
                    Certificate = $muxCert.Certificate
                }
            }
        }

        # loop through all the objects to perform PUT operation against the virtualServer resource
        # to update the base64 encoding for the certificate that NC should use when communicating with the virtualServer resource
        foreach ($obj in $array) {
            "Updating certificate information for {0}" -f $obj.ResourceRef | Trace-Output
            $virtualServer = Get-SdnResource @ncRestParams -ResourceRef $obj.ResourceRef
            $encoding = [System.Convert]::ToBase64String($obj.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))

            if ($virtualServer.properties.certificate) {
                $virtualServer.properties.certificate = $encoding
            }
            else {
                # in instances where the certificate property does not exist, we will need to add it
                # this typically will occur if converting from CA issued certificate to self-signed certificate
                $virtualServer.properties | Add-Member -MemberType NoteProperty -Name 'certificate' -Value $encoding -Force
            }
            $putRestParams.Body = ($virtualServer | ConvertTo-Json -Depth 100)

            $endpoint = Get-SdnApiEndpoint -NcUri $sdnFabricDetails.NcUrl -ResourceRef $virtualServer.resourceRef
            $putRestParams.Uri = $endpoint

            $null = Invoke-RestMethodWithRetry @putRestParams
            if (-NOT (Confirm-ProvisioningStateSucceeded -NcUri $putRestParams.Uri @confirmStateParams)) {
                throw New-Object System.Exception("ProvisioningState is not succeeded")
            }
            else {
                "Successfully updated the certificate information for {0}" -f $obj.ResourceRef | Trace-Output
            }

            # after we have generated the certificates and updated the servers to use the new certificate
            # we will want to go and locate certificates that may conflict with the new certificate
            "Checking certificates on {0} that match {1}" -f $obj.managementAddress, $obj.Certificate.Subject | Trace-Output
            $certsToExamine = Invoke-PSRemoteCommand -ComputerName $obj.managementAddress -Credential $Credential -ScriptBlock {
                param([Parameter(Mandatory = $true)]$param1)
                $certs = Get-SdnCertificate -Path 'Cert:\LocalMachine\My' -Subject $param1.Subject
                if ($certs.Count -ge 2) {
                    $certToRemove = $certs | Where-Object {$_.Thumbprint -ine $param1.Thumbprint}

                    return $certToRemove
                }
            } -ArgumentList $obj.Certificate

            if ($certsToExamine) {
                "`nMultiple certificates detected for Subject: {0}. Examine the certificates and cleanup if no longer needed." -f $obj.Certificate.Subject | Trace-Output -Level:Warning
                foreach ($cert in $certsToExamine) {
                    "`t[{0}] Thumbprint: {1}" -f $cert.PSComputerName, $cert.Thumbprint | Trace-Output -Level:Warning
                }

                Write-Host "" # insert empty line for better readability
            }

            # restart the slb mux service on the mux
            $null = Invoke-PSRemoteCommand -ComputerName $obj.managementAddress -Credential $Credential -ScriptBlock {
                Restart-Service -Name SlbMux -Force
            }
        }

        "Certificate rotation for Load Balancer Muxes has completed" | Trace-Output -Level:Success
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
