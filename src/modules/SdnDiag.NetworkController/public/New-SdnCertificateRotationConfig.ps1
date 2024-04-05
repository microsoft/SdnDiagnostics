function New-SdnCertificateRotationConfig {
    <#
    .SYNOPSIS
        Prepare the Network Controller Ceritifcate Rotation Configuration to determine which certificates to be used.
    .PARAMETER NetworkController
        Specifies the name the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> New-SdnCertificateRotationConfig
    .EXAMPLE
        PS> New-SdnCertificateRotationConfig -NetworkController 'NC01' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Rest','NetworkController','Server','LoadBalancerMux')]
        [String]$CertificateType
    )

    $CertificateRotationConfig = @{}
    $getNewestCertScript = {
        param([string]$param1, [string]$param2, [string]$param3)

        if ([string]::IsNullOrWhiteSpace($param2)) {
            $cert = Get-SdnCertificate -Path $param1 -Subject $param2 -NetworkControllerOid
        }
        else {
            $cert = Get-SdnCertificate -Path $param1 -Subject $param3 -NetworkControllerOid
        }
        # get the certificate that has the expiration date furthest in the future
        # we also want to ensure we filter for certificates that have the Network Controller OID
        if ($cert) {
            $cert = $cert | Sort-Object -Property NotAfter -Descending | Select-Object -First 1
            return $cert.Thumbprint
        }

        return $null
    }

    try {
        $NcInfraInfo = Get-SdnNetworkControllerInfoOffline -NetworkController $NetworkController -Credential $Credential
        $CertificateRotationConfig["ClusterCredentialType"] = $NcInfraInfo.ClusterCredentialType

        switch ($CertificateType) {
            'Rest' {
                $CertificateRotationConfig["NcRestCert"] = Invoke-PSRemoteCommand @{
                    ComputerName = $NetworkController
                    ScriptBlock  = $getNewestCertScript
                    Credential  = $Credential
                    ArgumentList =  @("Cert:\LocalMachine\My", "CN=$($NcInfraInfo.NcRestName)")
                }
            }
        }

        if($NcInfraInfo.ClusterCredentialType -eq "X509"){
            foreach ($ncNode in $($NcInfraInfo.NodeList)) {
                Trace-Output -Message "Looking for Node Cert for Node: $($ncNode.NodeName), IpAddressOrFQDN: $($ncNode.IpAddressOrFQDN)" -Level:Verbose
                $ncNodeCert = Invoke-PSRemoteCommand -ComputerName $ncNode.IpAddressOrFQDN -ScriptBlock $getNewestCertScript -Credential $Credential
                $CertificateRotationConfig[$ncNode.NodeName.ToLower()] = $ncNodeCert
            }
        }

        return $CertificateRotationConfig
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
