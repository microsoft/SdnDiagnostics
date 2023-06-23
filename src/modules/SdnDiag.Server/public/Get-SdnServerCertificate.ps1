function Get-SdnServerCertificate {
    <#
        .SYNOPSIS
        Returns the certificate used by the SDN Host Agent.
    #>

    [CmdletBinding()]
    param()

    try {
        $serverCert = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters' -Name 'HostAgentCertificateCName'
        $subjectName = "CN={0}" -f $serverCert
        $certificate = Get-SdnCertificate -Subject $subjectName
        return $certificate
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
