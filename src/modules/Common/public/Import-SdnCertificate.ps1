function Import-SdnCertificate {
    <#
    .SYNOPSIS
        Imports certificates and private keys from a Personal Information Exchange (PFX) file to the destination store.
    .PARAMETER FilePath
        Specifies the full path to the PFX file of the secured file.
    .PARAMETER CertStore
        Specifies the path of the store to which certificates will be imported. If paramater is not specified, defaults to Cert:\LocalMachine\Root.
    .PARAMETER CertPassword
        Specifies the password for the imported PFX file in the form of a secure string.
    .EXAMPLE
        PS> Import-SdnCertificate -FilePath c:\certs\cert.pfx -CertStore Cert:\LocalMachine\Root
    .EXAMPLE
        PS> Import-SdnCertificate -FilePath c:\certs\cert.pfx -CertStore Cert:\LocalMachine\Root -Password $secureString
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$FilePath,

        [Parameter(Mandatory = $true)]
        [System.String]$CertStore,

        [Parameter(Mandatory = $false)]
        [System.Security.SecureString]$CertPassword
    )

    $trustedRootStore = 'Cert:\LocalMachine\Root'
    $fileInfo = Get-Item -Path $FilePath

    $certObject = @{
        SelfSigned = $false
        CertInfo = $null
        CerFileInfo = $null
    }

    if ($CertPassword) {
        $pfxData = (Get-PfxData -FilePath $fileInfo.FullName -Password $CertPassword).EndEntityCertificates
    }
    else {
        $pfxData = Get-PfxCertificate -FilePath $fileInfo.FullName
    }

    $certExists = Get-ChildItem -Path $CertStore | Where-Object {$_.Thumbprint -ieq $pfxData.Thumbprint}
    if ($certExists) {
        "{0} already exists under {1}" -f $certExists.Thumbprint, $CertStore | Trace-Output
        $certObject.CertInfo = $certExists
    }
    else {
        "Importing certificate file {0} with Thumbprint: {1} to {2}" -f $fileInfo.FullName, $pfxData.Thumbprint, $CertStore | Trace-Output
        if ($pfxData.HasPrivateKey) {
            $importCert = Import-PfxCertificate -FilePath $fileInfo.FullName -CertStoreLocation $CertStore -Password $CertPassword -Exportable -ErrorAction Stop
            Set-SdnCertificateAcl -Path $CertStore -Thumbprint $importCert.Thumbprint
        }
        else {
            $importCert = Import-Certificate -FilePath $fileInfo.FullName -CertStoreLocation $CertStore -ErrorAction Stop
        }

        $certObject.CertInfo = $importCert
    }

    # determine if the certificates being used are self signed
    if ($certObject.CertInfo.Subject -ieq $certObject.CertInfo.Issuer) {
        "Detected the certificate subject and issuer are the same. Setting SelfSigned to true" | Trace-Output -Level:Verbose
        $certObject.SelfSigned = $true

        # check to see if we installed to root store with above operation
        # if it is not, then we want to check the root store to see if this certificate has already been installed
        # and finally if does not exist, then export the certificate from current store and import into trusted root store
        if ($CertStore -ine $trustedRootStore) {
            $selfSignedCerExists = Get-ChildItem -Path $trustedRootStore | Where-Object {$_.Thumbprint -ieq $certObject.CertInfo.Thumbprint}
            [System.String]$selfSignedCerPath = "{0}\{1}.cer" -f (Split-Path $fileInfo.FullName -Parent), ($certObject.CertInfo.Subject).Replace('=','_')
            $selfSignedCer = Export-Certificate -Cert $certObject.CertInfo -FilePath $selfSignedCerPath -ErrorAction Stop
            $certObject.CerFileInfo = $selfSignedCer

            if (-NOT ($selfSignedCerExists)) {
                # import the certificate to the trusted root store
                "Importing certificate file {0} to {1}" -f $selfSignedCer.FullName, $trustedRootStore | Trace-Output
                $null = Import-Certificate -FilePath $selfSignedCer.FullName -CertStoreLocation $trustedRootStore -ErrorAction Stop
            }
            else {
                "{0} already exists under {1}" -f $certObject.CertInfo.Thumbprint, $trustedRootStore | Trace-Output
            }
        }
    }

    return $certObject
}
