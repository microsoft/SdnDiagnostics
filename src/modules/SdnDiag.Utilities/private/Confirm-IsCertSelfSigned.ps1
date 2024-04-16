function Confirm-IsCertSelfSigned {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    if ($Certificate.Issuer -eq $Certificate.Subject) {
        return $true
    }

    return $false
}
