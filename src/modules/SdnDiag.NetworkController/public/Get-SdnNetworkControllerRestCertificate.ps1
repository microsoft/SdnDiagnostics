function Get-SdnNetworkControllerRestCertificate {
    <#
    .SYNOPSIS
        Returns the current Network Controller REST Certificate
    #>

    try {
        $networkController = Get-SdnNetworkController
        $ncRestCertThumprint = $($networkController.ServerCertificate.Thumbprint).ToString()
        $certificate = Get-SdnCertificate -Path 'Cert:\LocalMachine\My' -Thumbprint $ncRestCertThumprint

        if ($null -eq $certificate) {
            throw New-Object System.NullReferenceException("Unable to locate Network Controller Rest Certificate")
        }

        return $certificate
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
