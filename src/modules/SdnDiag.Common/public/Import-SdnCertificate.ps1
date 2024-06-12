function Import-SdnCertificate {
    <#
    .SYNOPSIS
        Imports certificates (CER) and private keys from a Personal Information Exchange (PFX) file to the destination store.
    .PARAMETER FilePath
        Specifies the full path to the PFX or CER file.
    .PARAMETER CertStore
        Specifies the path of the store to which certificates will be imported. If paramater is not specified, defaults to Cert:\LocalMachine\Root.
    .PARAMETER CertPassword
        Specifies the password for the imported PFX file in the form of a secure string.
    .EXAMPLE
        PS> Import-SdnCertificate -FilePath c:\certs\cert.pfx -CertStore Cert:\LocalMachine\Root
    .EXAMPLE
        PS> Import-SdnCertificate -FilePath c:\certs\cert.pfx -CertStore Cert:\LocalMachine\Root -Password $secureString
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$FilePath,

        [Parameter(Mandatory = $true)]
        [System.String]$CertStore,

        [Parameter(Mandatory = $false)]
        [System.Security.SecureString]$CertPassword
    )

    $trustedRootStore = 'Cert:\LocalMachine\Root'
    $certObject = [PSCustomObject]@{
        SelfSigned = $false
        CertInfo = $null
        SelfSignedCertFileInfo = $null
    }

    try {
        $fileInfo = Get-Item -Path $FilePath -ErrorAction Stop
        switch ($fileInfo.Extension) {
            '.pfx' {
                if ($CertPassword) {
                    $certData = (Get-PfxData -FilePath $fileInfo.FullName -Password $CertPassword).EndEntityCertificates
                }
                else {
                    $certData = Get-PfxCertificate -FilePath $fileInfo.FullName
                }
            }

            '.cer' {
                $certData = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                $certData.Import($fileInfo)
            }

            default {
                throw New-Object System.NotSupportedException("Unsupported certificate extension")
            }
        }

        $certExists = Get-SdnCertificate -Path $CertStore -Thumbprint $certData.Thumbprint
        if ($certExists) {
            $certObject.CertInfo = $certExists
        }
        else {
            "Importing [Subject: $($_.Subject), Thumbprint: $($_.Thumbprint)] to $CertStore" | Trace-Output
            if ($certData.HasPrivateKey) {
                $importCert = Import-PfxCertificate -FilePath $fileInfo.FullName -CertStoreLocation $CertStore -Password $CertPassword -Exportable -ErrorAction Stop
                Set-SdnCertificateAcl -Path $CertStore -Thumbprint $importCert.Thumbprint
            }
            else {
                $importCert = Import-Certificate -FilePath $fileInfo.FullName -CertStoreLocation $CertStore -ErrorAction Stop
            }

            $certObject.CertInfo = $importCert
        }

        # determine if the certificates being used are self signed
        if (Confirm-IsCertSelfSigned -Certificate $certObject.CertInfo) {
            $certObject.SelfSigned = $true

            # check to see if we installed to root store with above operation
            # if it is not, then we want to check the root store to see if this certificate has already been installed
            # and finally if does not exist, then export the certificate from current store and import into trusted root store
            if ($CertStore -ine $trustedRootStore) {
                $selfSignedCerExists = Get-SdnCertificate -Path $trustedRootStore -Thumbprint $certObject.CertInfo.Thumbprint
                [System.String]$selfSignedCerPath = "{0}\{1}.cer" -f (Split-Path $fileInfo.FullName -Parent), ($certObject.CertInfo.Subject).Replace('=','_')
                $selfSignedCer = Export-Certificate -Cert $certObject.CertInfo -FilePath $selfSignedCerPath -ErrorAction Stop
                $certObject.SelfSignedCertFileInfo = $selfSignedCer

                if (-NOT ($selfSignedCerExists)) {
                    # import the certificate to the trusted root store
                    "Importing public key to {0}" -f $trustedRootStore | Trace-Output
                    $null = Import-Certificate -FilePath $selfSignedCer.FullName -CertStoreLocation $trustedRootStore -ErrorAction Stop
                }
                else {
                    "{0} already exists under {1}" -f $certObject.CertInfo.Thumbprint, $trustedRootStore | Trace-Output -Level:Verbose
                }
            }
        }

        return $certObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }

    return $null
}
