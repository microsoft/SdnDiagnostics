function New-SdnCertificate {
    <#
    .SYNOPSIS
        Creates a new self-signed certificate for use with SDN fabric.
    .PARAMETER Subject
        Specifies the string that appears in the subject of the new certificate. This cmdlet prefixes CN= to any value that does not contain an equal sign.
    .PARAMETER CertStoreLocation
        Specifies the certificate store in which to store the new certificate. If paramater is not specified, defaults to Cert:\LocalMachine\My.
    .PARAMETER NotAfter
        Specifies the date and time, as a DateTime object, that the certificate expires. To obtain a DateTime object, use the Get-Date cmdlet. The default value for this parameter is one year after the certificate was created.
    .EXAMPLE
        PS> New-SdnCertificate -Subject rest.sdn.contoso -CertStoreLocation Cert:\LocalMachine\My
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.String]$Subject,

        [Parameter(Mandatory = $false)]
        [ValidateScript({
            if ($_ -notlike "cert:\*") {
                throw New-Object System.FormatException("Invalid path")
            }

            return $true
        })]
        [System.String]$CertStoreLocation = 'Cert:\LocalMachine\My',

        [Parameter(Mandatory = $true)]
        [System.DateTime]$NotAfter
    )

    try {
        "Generating certificate with subject {0} under {1}" -f $Subject, $CertStoreLocation | Trace-Output

        $selfSignedCert = New-SelfSignedCertificate -Type Custom -KeySpec KeyExchange -Subject $Subject `
            -KeyExportPolicy Exportable -HashAlgorithm sha256 -KeyLength 2048 `
            -CertStoreLocation $CertStoreLocation -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2,1.3.6.1.4.1.311.95.1.1.1") `
            -NotAfter $NotAfter

        if ($selfSignedCert) {
            "Successfully generated self signed certificate`n`tSubject: {0}`n`tThumbprint: {1}`n`tNotAfter: {2}" `
            -f $selfSignedCert.Subject, $selfSignedCert.Thumbprint, $selfSignedCert.NotAfter | Trace-Output

            Set-SdnCertificateAcl -Path $CertStoreLocation -Thumbprint $selfSignedCert.Thumbprint
        }

        return $selfSignedCert
    }
    catch {
       $_ | Trace-Output -Level:Error
    }
}
