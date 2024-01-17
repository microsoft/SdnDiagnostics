function Get-SdnMuxCertificate {
    <#
        .SYNOPSIS
        Returns the certificate used by the SDN Load Balancer Mux.
    #>

    [CmdletBinding()]
    param ()

    try {
        $muxCert = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SlbMux' -Name 'MuxCert'
        $subjectName = "CN={0}" -f $muxCert
        $certificate = Get-SdnCertificate -Subject $subjectName -Path 'Cert:\LocalMachine\My'
        return $certificate
    }
    catch {
        $_ | Trace-Exception
    }
}
