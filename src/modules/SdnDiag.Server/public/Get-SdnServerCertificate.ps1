function Get-SdnServerCertificate {
    <#
        .SYNOPSIS
            Returns the certificate used by the Network Controller Host Agent.
        .PARAMETER NetworkControllerOid
            Specifies to return only the certificate that has the specified Network Controller OID.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [switch]$NetworkControllerOid
    )

    try {
        $serverCert = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters' -Name 'HostAgentCertificateCName'
        $subjectName = "CN={0}" -f $serverCert
        $certificate = Get-SdnCertificate -Subject $subjectName -Path 'Cert:\LocalMachine\My' -NetworkControllerOid:$NetworkControllerOid

        if ($null -eq $certificate) {
            if ($NetworkControllerOid) {
                throw New-Object System.NullReferenceException("Failed to locate certificate for NCHostAgent containing Network Controller OID")
            }
            else {
                throw New-Object System.NullReferenceException("Failed to locate certificate for NCHostAgent")
            }
        }

        return $certificate
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
