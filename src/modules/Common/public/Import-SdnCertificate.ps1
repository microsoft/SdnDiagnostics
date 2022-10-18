function Import-SdnCertificate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$FilePath,

        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$CertPassword
    )

    $certStore = 'Cert:\LocalMachine\My'
    $trustedRootStore = 'Cert:\LocalMachine\Root'

    $fileInfo = Get-Item -Path $FilePath
    $pfxData = Get-PfxData -FilePath $fileInfo.FullName -Password $CertPassword

    $certObject = @{
        SelfSigned = $false
        CertInfo = $null
    }

    # if the cert already exists within the cert store, we want to skip the installation process
    # and return back the x509Certificate2 object
    $certExists = Get-ChildItem -Path $certStore | Where-Object {$_.Thumbprint -ieq $pfxData.EndEntityCertificates.Thumbprint}
    if ($certExists) {
        "{0} is already installed under {1}" -f $certExists.Thumbprint, $certExists.DirectoryName | Trace-Output
        $certObject.CertInfo = $certExists
    }
    else {
        "Importing {0} with Thumbprint: {1} to {2}" -f $fileInfo.FullName, $pfxData.EndEntityCertificates.Thumbprint, $certStore | Trace-Output
        $pfxCertificate = Import-PfxCertificate -FilePath $fileInfo.FullName -CertStoreLocation $certStore -Password $CertPassword -Exportable
        $certObject.CertInfo = $pfxCertificate
    }

    Set-SdnCertificateAcl -Path $certStore -Thumbprint $certObject.CertInfo.Thumbprint

    # determine if the certificates being used are self signed
    if ($certObject.CertInfo.Subject -ieq $certObject.CertInfo.Issuer) {
        "Detected the certificate subject and issuer are the same. Setting SelfSigned to true" | Trace-Output
        $certObject.SelfSigned = $selfSigned

        [System.String]$selfSignedCerPath = "{0}\{1}.cer" -f (Split-Path $fileInfo.FullName -Parent), ($pfxCertificate.EndEntityCertificates.Subject).Replace('=','_')
        $selfSignedCer = Export-PfxCertificate -Cert $pfxCertificate -FilePath $selfSignedCerPath .\.build-Password $CertPassword -CryptoAlgorithmOption AES256_SHA256

        "Importing {0} to {1}" -f $pfxCertificate.FullName, $trustedRootStore | Trace-Output
        $cert = Import-Certificate -FilePath $selfSignedCer.FullName -CertStoreLocation $trustedRootStore
        if ($cert) {
            "Successfully imported {0}" -f $cert.Thumbprint | Trace-Output
            $certObject | Add-Member -MemberType NoteProperty -Name 'CerFile' -Value $cert
        }
    }

    return $certObject
}
