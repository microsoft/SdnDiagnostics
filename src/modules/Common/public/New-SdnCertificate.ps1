# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function New-SdnCertificate {
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
        $selfSignedCert = New-SelfSignedCertificate -Type Custom -KeySpec KeyExchange -Subject $Subject `
            -KeyExportPolicy Exportable -HashAlgorithm sha256 -KeyLength 2048 `
            -CertStoreLocation $CertStoreLocation -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2") `
            -NotAfter $NotAfter

        if ($selfSignedCert) {
            "Successfully generated self signed certificate`n`tSubject: {0}`n`tThumbprint: {1}`n`tNotAfter: {2}" `
            -f $selfSignedCert.Subject, $selfSignedCert.Thumbprint, $selfSignedCert.NotAfter | Trace-Output

            Set-SdnCertificateAcl -Path $CertStoreLocation -Thumbprint $selfSignedCert.Thumbprint
        }

        return $selfSignedCert
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
