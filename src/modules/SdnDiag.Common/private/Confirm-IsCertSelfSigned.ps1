function Confirm-IsCertSelfSigned {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    if ($Certificate.Issuer -eq $Certificate.Subject) {
        "Detected the certificate subject and issuer are the same. Setting SelfSigned to true" | Trace-Output -Level:Verbose
        return $true
    }

    return $false
}
