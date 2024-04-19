function Get-SdnNetworkControllerRestCertificate {
    <#
    .SYNOPSIS
        Returns the current Network Controller REST Certificate
    #>

    Confirm-IsNetworkController

    try {
        $networkController = Get-SdnNetworkController -ErrorAction 'Stop'
        $ncRestCertThumprint = $($networkController.ServerCertificate.Thumbprint).ToString()
        $certificate = Get-SdnCertificate -Path 'Cert:\LocalMachine\My' -Thumbprint $ncRestCertThumprint -ErrorAction 'Stop'
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }

    if ($null -eq $certificate) {
        throw New-Object System.NullReferenceException("Unable to locate Network Controller Rest Certificate")
    }

    return $certificate
}
