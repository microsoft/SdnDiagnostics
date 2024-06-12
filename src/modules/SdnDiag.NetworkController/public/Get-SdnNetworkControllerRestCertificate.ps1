function Get-SdnNetworkControllerRestCertificate {
    <#
    .SYNOPSIS
        Returns the current Network Controller REST Certificate
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    Confirm-IsNetworkController

    try {
        $networkController = Get-SdnNetworkController -NetworkController $env:COMPUTERNAME -Credential $Credential
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
