function Get-SdnMuxCertificate {
    <#
        .SYNOPSIS
            Returns the certificate used by the SDN Load Balancer Mux.
        .PARAMETER NetworkControllerOid
            Specifies to return only the certificate that has the specified Network Controller OID.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [switch]$NetworkControllerOid
    )

    try {
        $muxCert = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SlbMux' -Name 'MuxCert'
        $subjectName = "CN={0}" -f $muxCert
        $certificate = Get-SdnCertificate -Subject $subjectName -Path 'Cert:\LocalMachine\My' -NetworkControllerOid:$NetworkControllerOid

        if ($null -eq $certificate) {
            if ($NetworkControllerOid) {
                throw New-Object System.NullReferenceException("Failed to locate certificate for Load Balancer Mux containing Network Controller OID")
            }
            else {
                throw New-Object System.NullReferenceException("Failed to locate certificate for Load Balancer Mux")
            }
        }

        return $certificate
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
