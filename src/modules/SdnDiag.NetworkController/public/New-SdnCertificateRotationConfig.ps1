function New-SdnCertificateRotationConfig {
    <#
    .SYNOPSIS
        Prepare the Network Controller Certificate Rotation Configuration to determine which certificates to be used.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> New-SdnCertificateRotationConfig -CertificateType 'Rest'
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [CertType]$CertificateType,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [switch]$NetworkControllerOid
    )

    $certRotateConfig = [CertRotateConfig]::new()

    try {
        $ncInfraInfo = Get-SdnNetworkControllerInfoOffline
        $certRotateConfig.ClusterCredentialType = $ncInfraInfo.ClusterCredentialType
        [string]$restSubjectName = "CN=$($NcInfraInfo.NcRestName)"
        [uri]$ncUrl = "https://$($NcInfraInfo.NcRestName)"

        switch ($CertificateType) {
            'LoadBalancerMuxNodeCert' {
                $servers = Get-SdnLoadBalancerMux -NcUri $ncUrl -Credential $NcRestCredential
                $servers | ForEach-Object {
                    $virtualServer = Get-SdnResource -NcUri $ncUrl -ResourceRef $_.properties.virtualServer.resourceRef
                    $connection = $virtualServer.properties.connections | Where-Object { $_.credentialType -ieq "X509Certificate" -or $_.credentialType -ieq "X509CertificateSubjectName" }
                    $managementAddress = $connection.managementAddresses[0]

                    "Retrieving latest certificate from $managementAddress" | Trace-Output
                    $cert = Invoke-PSRemoteCommand -ComputerName $managementAddress -ScriptBlock {
                        param([switch]$arg0)
                        return (Get-SdnMuxCertificate -NetworkControllerOid:$arg0)
                    } -ArgumentList @($NetworkControllerOid) -Credential $Credential -ErrorAction Stop

                    $newestCert = $cert | Sort-Object -Property NotAfter -Descending | Select-Object -First 1
                    $certRotateConfig.NodeCerts += [LoadBalancerMuxNodeCert]@{
                        Thumbprint      = $newestCert.Thumbprint
                        SubjectName     = $newestCert.Subject
                        IpAddressOrFQDN = $managementAddress
                        NodeName        = $newestCert.PSComputerName
                        ResourceRef     = $_.ResourceRef
                        IsSelfSigned = (Confirm-IsCertSelfSigned -Certificate $newestCert)
                    }
                }
            }

            'NetworkControllerNodeCert' {
            }

            'RestCertificate' {
                # grab the rest certificate with the latest expiration date
                $restCertificate = Get-SdnCertificate -Path 'Cert:\LocalMachine\My' -Subject $restSubjectName -NetworkControllerOid:$NetworkControllerOid `
                | Sort-Object -Property NotAfter -Descending | Select-Object -First 1

                if ($null -eq $restCertificate) {
                    throw New-Object System.NullReferenceException("Failed to locate Rest certificate")
                }

                $CertRotateConfig.RestCertificate = [RestCertificate]@{
                    CertificateType = 'Rest'
                    Thumbprint = $restCertificate.Thumbprint
                    SubjectName = $restCertificate.Subject
                    IsSelfSigned = (Confirm-IsCertSelfSigned -Certificate $restCertificate)
                }
            }

            'ServerNodeCert' {
                $servers = Get-SdnServer -NcUri $ncUrl -Credential $NcRestCredential
                $servers | ForEach-Object {
                    $connection = $_.properties.connections | Where-Object { $_.credentialType -ieq "X509Certificate" -or $_.credentialType -ieq "X509CertificateSubjectName" }
                    $managementAddress = $connection.managementAddresses[0]

                    "Retrieving latest certificate from $managementAddress" | Trace-Output
                    $cert = Invoke-PSRemoteCommand -ComputerName $managementAddress -ScriptBlock {
                        param([switch]$arg0)
                        return (Get-SdnServerCertificate -NetworkControllerOid:$arg0)
                    } -ArgumentList @($NetworkControllerOid) -Credential $Credential -ErrorAction Stop

                    $newestCert = $cert | Sort-Object -Property NotAfter -Descending | Select-Object -First 1
                    $certRotateConfig.NodeCerts += [ServerNodeCert]@{
                        Thumbprint      = $newestCert.Thumbprint
                        SubjectName     = $newestCert.Subject
                        IpAddressOrFQDN = $managementAddress
                        NodeName        = $newestCert.PSComputerName
                        ResourceRef     = $_.ResourceRef
                        IsSelfSigned = (Confirm-IsCertSelfSigned -Certificate $newestCert)
                    }
                }
            }
        }

        return $certRotateConfig
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
