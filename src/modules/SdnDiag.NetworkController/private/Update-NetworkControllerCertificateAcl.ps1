function Update-NetworkControllerCertificateAcl {
    <#
    .SYNOPSIS
        Update the Network Controller Certificate to grant Network Service account read access to the private key.
    .PARAMETER NcNodeList
        The NcNodeList that retrieved via Get-SdnNetworkControllerInfoOffline.
    .PARAMETER CertRotateConfig
        The Config generated by New-SdnCertificateRotationConfig to include NC REST certificate thumbprint and node certificate thumbprint.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $NcNodeList,
        [Parameter(Mandatory = $true)]
        [hashtable]
        $CertRotateConfig,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $NcRestCertThumbprint = $CertRotateConfig["NcRestCert"]

        foreach ($ncNode in $NcNodeList) {
            $ncNodeCertThumbprint = $CertRotateConfig[$ncNode.NodeName.ToLower()]
            Invoke-PSRemoteCommand -ComputerName $ncNode.IpAddressOrFQDN -ScriptBlock {
                Set-SdnCertificateAcl -Path 'Cert:\LocalMachine\My' -Thumbprint $using:NcRestCertThumbprint
            } -Credential $Credential

            if ($CertRotateConfig["ClusterCredentialType"] -ieq "X509") {
                Invoke-PSRemoteCommand -ComputerName $ncNode.IpAddressOrFQDN -ScriptBlock {
                    Set-SdnCertificateAcl -Path 'Cert:\LocalMachine\My' -Thumbprint $using:ncNodeCertThumbprint
                } -Credential $Credential
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
