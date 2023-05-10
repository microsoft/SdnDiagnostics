function Start-SdnServerCertificateRotation {
    <#
    .SYNOPSIS
        Performs a certificate rotation operation for the Servers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action on the Server and Network Controller nodes. The default is the current user.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    .PARAMETER GenerateCertificate
        Switch to determine if certificate rotate function should generate self-signed certificates.
    .PARAMETER CertPassword
        SecureString password for accessing the .pfx files, or if using -GenerateCertificate, what the .pfx files will be encrypted with.
    .PARAMETER NotAfter
        Expiration date when using -GenerateCertificate. If ommited, defaults to 3 years.
    .PARAMETER Force
        Switch to force the rotation without being prompted, when Service Fabric is unhealthy.
    #>

    [CmdletBinding(DefaultParameterSetName = 'GenerateCertificate')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'GenerateCertificate')]
        [System.String]$NetworkController,

        [Parameter(Mandatory = $true, ParameterSetName = 'GenerateCertificate')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Parameter(Mandatory = $false, ParameterSetName = 'GenerateCertificate')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'GenerateCertificate')]
        [Switch]$GenerateCertificate,

        [Parameter(Mandatory = $true, ParameterSetName = 'GenerateCertificate')]
        [System.Security.SecureString]$CertPassword,

        [Parameter(Mandatory = $false, ParameterSetName = 'GenerateCertificate')]
        [datetime]$NotAfter = (Get-Date).AddYears(3),

        [Parameter(Mandatory = $false, ParameterSetName = 'GenerateCertificate')]
        [switch]$Force
    )

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
    $headers = @{"Accept"="application/json"}
    $content = "application/json; charset=UTF-8"

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
        $sdnFabricDetails = Get-SdnInfrastructureInfo -NetworkController $NetworkController -Credential $Credential -NcRestCredential $NcRestCredential -ErrorAction Stop
        $servers = Get-SdnServer -NcUri $sdnFabricDetails.NcUrl -Credential $NcRestCredential -ErrorAction Stop

        # before we proceed with anything else, we want to make sure that all the Network Controllers and MUXes within the SDN fabric are running the current version
        Install-SdnDiagnostics -ComputerName $sdnFabricDetails.NetworkController -ErrorAction Stop
        Install-SdnDiagnostics -ComputerName $sdnFabricDetails.Server -ErrorAction Stop

        #####################################
        #
        # Create Certificate (Optional)
        #
        #####################################

        if ($PSCmdlet.ParameterSetName -ieq 'GenerateCertificate') {
            "== STAGE: CREATE SELF SIGNED CERTIFICATES ==" | Trace-Output

            # retrieve the corresponding managementAddress from each of the server resources
            # and invoke remote operation to the server to generate the self-signed certificate
            foreach ($server in $servers) {
                $serverConnection = $server.properties.connections | Where-Object {$_.credentialType -ieq "X509Certificate"}
                $managementAddress = $serverConnection.managementAddresses[0]

                $serverCert = Invoke-PSRemoteCommand -ComputerName $managementAddress -Credential $Credential -ScriptBlock {
                    param(
                        [Parameter(Position = 0)][DateTime]$param1,
                        [Parameter(Position = 1)][PSCredential]$param2,
                        [Parameter(Position = 2)][String]$param3,
                        [Parameter(Position = 3)][System.Object]$param4
                    )

                    New-SdnServerCertificate -NotAfter $param1 -Credential $param2 -Path $param3 -FabricDetails $param4
                } -ArgumentList @($NotAfter, $Credential, $CertPath.FullName, $sdnFabricDetails)

                $array += [PSCustomObject]@{
                    ManagementAddress = $managementAddress
                    ResourceRef = $server.resourceRef
                    Certificate = $serverCert.Certificate
                }
            }
        }

        # loop through all the objects to perform PUT operation against the server resource
        # to update the base64 encoding for the certificate that NC should use when communicating with the server resource
        foreach ($obj in $array) {
            "Updating certificate information for {0}" -f $obj.ResourceRef | Trace-Output
            $server = Get-SdnResource -NcUri $sdnFabricDetails.NcUrl -Credential $NcRestCredential -ResourceRef $obj.ResourceRef
            $encoding = [System.Convert]::ToBase64String($obj.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))

            $endpoint = Get-SdnApiEndpoint -NcUri $sdnFabricDetails.NcUrl  -ResourceRef $server.resourceRef
            $server.properties.certificate = $encoding
            $jsonBody = $server | ConvertTo-Json -Depth 100

            $null = Invoke-RestMethodWithRetry -Method 'Put' -UseBasicParsing -Uri $endpoint -Headers $headers -ContentType $content -Body $jsonBody -Credential $NcRestCredential
            if (-NOT (Confirm-ProvisioningStateSucceeded -Uri $endpoint -Credential $NcRestCredential -UseBasicParsing)) {
                throw New-Object System.Exception("ProvisioningState is not succeeded")
            }
            else {
                "Successfully updated the certificate information for {0}" -f $obj.ResourceRef | Trace-Output
            }

            # after we have generated the certificates and updated the servers to use the new certificate
            # we will want to go and remove any old certificates as this will cause issues in older builds
            "Removing the old certificates on {0} that match {1}" -f $obj.managementAddress, $obj.Certificate.Subject | Trace-Output
            $certsRemoved = Invoke-PSRemoteCommand -ComputerName $obj.managementAddress -Credential $Credential -ScriptBlock {
                param([Parameter(Mandatory = $true)]$param1)
                $certs = Get-SdnCertificate -Path 'Cert:\LocalMachine\My' -Subject $param1.Subject
                if ($certs.Count -ge 2) {
                    $certToRemove = $certs | Where-Object {$_.Thumbprint -ine $param1.Thumbprint}
                    $certToRemove | Remove-Item

                    return $certToRemove
                }
            } -ArgumentList $obj.Certificate

            if ($certsRemoved) {
                foreach ($cert in $certsRemoved) {
                    "Removed certificate subject {0} and thumbprint {1}" -f $cert.Subject, $cert.Thumbprint | Trace-Output
                }
            }

            # restart nchostagent on server
            $null = Invoke-PSRemoteCommand -ComputerName $obj.managementAddress -Credential $Credential -ScriptBlock {
                Restart-Service -Name NcHostAgent -Force
            }
        }

        "Certificate rotation for Servers has completed" | Trace-Output -Level:Success
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
