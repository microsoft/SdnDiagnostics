function Test-SdnCertificateRotationConfig {
    <#
    .SYNOPSIS
        Validate the Cert Rotation Config provided is correct. Ensure certificates specified present on the machine.
    .PARAMETER NcNodeList
        The NcNodeList that retrieved via Get-SdnNetworkControllerInfoOffline.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER CertRotateConfig
        The Config generated by New-SdnCertificateRotationConfig to include NC REST certificate thumbprint and node certificate thumbprint.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$NcNodeList,

        [Parameter(Mandatory = $true)]
        [hashtable]$CertRotateConfig,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {

        if ([string]::IsNullOrEmpty($CertRotateConfig["NcRestCert"])) {
            Trace-Output -Message "NcRestCert not specified in CertRotateConfig" -Level:Error
            return $false
        }

        $ncRestCert = $CertRotateConfig["NcRestCert"]
        foreach ($ncNode in $NcNodeList) {
            if ($CertRotateConfig["ClusterCredentialType"] -ieq "X509") {
                $nodeCert = $CertRotateConfig[$ncNode.NodeName.ToLower()]
                if ([string]::IsNullOrEmpty($nodeCert)) {
                    Trace-Output -Message "The ClusterCredentialType is X509 but Node $($ncNode.NodeName) does not have certificate specified" -Level:Error
                    return $false
                }
                else {
                    $certValid = Invoke-PSRemoteCommand -ComputerName $ncNode.IpAddressOrFQDN -Credential $Credential -ScriptBlock {
                        param([Parameter(Position = 0)][String]$param1)
                        $nodeCertObj = Get-SdnCertificate -Path "Cert:\LocalMachine\My" -Thumbprint $param1
                        if ($null -eq $nodeCertObj) {
                            return $false
                        }
                        else {
                            if ($nodeCertObj.NotAfter -le (Get-Date)) {
                                return $false
                            }
                        }
                        return $true
                    } -ArgumentList $nodeCert

                    if (!$certValid) {
                        Trace-Output -Message "Node $($ncNode.NodeName) does not have validate Node certificate with thumbprint $nodeCert installed" -Level:Error
                        return $false
                    }
                }
            }

            $certValid = Invoke-PSRemoteCommand -ComputerName $ncNode.IpAddressOrFQDN -Credential $Credential -ScriptBlock {
                param([Parameter(Position = 0)][String]$param1)
                $ncRestCertObj = Get-SdnCertificate -Path "Cert:\LocalMachine\My" -Thumbprint $param1
                if ($null -eq $ncRestCertObj) {
                    return $false
                }
                else {
                    if ($ncRestCertObj.NotAfter -le (Get-Date)) {
                        return $false
                    }
                }
                return $true
            } -ArgumentList $ncRestCert

            if (!$certValid) {
                Trace-Output -Message "Node $($ncNode.NodeName) does not have validate NcRest certificate with thumbprint $ncRestCert installed" -Level:Error
                return $false
            }
        }
        return $true
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
