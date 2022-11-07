# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function New-SdnNetworkControllerCertificate {
    <#
    .SYNOPSIS
        Generate new Self-Signed Certificate to be used by Network Controller.
    .PARAMETER NetworkControllers
        Specify the list of Network Controllers need to generate certificate.
    .PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnInfrastructureInfo
    .EXAMPLE
        PS> Get-SdnInfrastructureInfo -NetworkController 'NC01' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String[]]
        $NetworkControllers,
        [Parameter(Mandatory = $false)]
        [datetime]
        $NotAfter = (Get-Date).AddYears(1),
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$CertPassword,
        [Parameter(Mandatory = $false)]
        [String]
        $ClusterAuthentication = "X509",
        [Parameter(Mandatory = $true)]
        [String]
        $NcRestName,
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,
        [Switch]
        $InstallCertificate
    )


    try {
        [System.String]$path = "$(Get-WorkingDirectory)\Cert_{0}" -f (Get-FormattedDateTimeUTC)
        "Creating directory {0}" -f $path | Trace-Output
        [System.IO.DirectoryInfo]$CertPath = New-Item -Path $path -ItemType Directory -Force

        $restCert = New-SdnCertificate -Subject "CN=$NcRestName" -NotAfter $NotAfter

        # after the certificate has been generated, we want to export the certificate using the $CertPassword provided by the operator
        # and save the file to directory. This allows the rest of the function to pick up these files and perform the steps as normal
        [System.String]$filePath = "$(Join-Path -Path $CertPath.FullName -ChildPath $NcRestName.ToLower().Replace('.','_').Replace('=','_').Trim()).pfx"
        "Exporting pfx certificate to {0}" -f $filePath | Trace-Output
        $null = Export-PfxCertificate -Cert $restCert -FilePath $filePath -Password $CertPassword -CryptoAlgorithmOption AES256_SHA256

        # generate NC node certificates if auth type is X509 certificate
        if ($ClusterAuthentication -ieq "X509") {
            "ClusterAuthentication is currently configured for {0}. Creating node certificates" -f $ClusterAuthentication | Trace-Output
            foreach ($controller in $NetworkControllers) {
                if (Test-ComputerNameIsLocal -ComputerName $controller) {
                    $nodeCertSubject = (Get-SdnNetworkControllerNodeCertificate).Subject
                }
                else {
                    $nodeCertSubject = Invoke-PSRemoteCommand -ComputerName $controller -Credential $Credential -ScriptBlock { (Get-SdnNetworkControllerNodeCertificate).Subject }
                }
                
                "Creating node certificate {0}" -f $nodeCertSubject | Trace-Output
                $selfSignedCert = New-SdnCertificate -Subject $nodeCertSubject -NotAfter $NotAfter

                # after the certificate has been generated, we want to export the certificate using the $CertPassword provided by the operator
                # and save the file to directory. This allows the rest of the function to pick up these files and perform the steps as normal
                [System.String]$filePath = "$(Join-Path -Path $CertPath.FullName -ChildPath $controller.ToString().ToLower().Replace('.','_').Trim()).pfx"
                "Exporting pfx certificate to {0}" -f $filePath | Trace-Output
                $null = Export-PfxCertificate -Cert $selfSignedCert -FilePath $filePath -Password $CertPassword -CryptoAlgorithmOption AES256_SHA256
            }
        }

        if($InstallCertificate){
            $rotateNCNodeCerts = $false
            if ($ClusterAuthentication -ieq "X509"){
                $rotateNCNodeCerts = $true
            }
            $sdnFabricDetails = [PSCustomObject]@{
                NetworkController = $NetworkControllers
            }

            Copy-CertificatesToFabric -CertPath $CertPath.FullName -CertPassword $CertPassword -FabricDetails $sdnFabricDetails -RotateNodeCertificates:$rotateNCNodeCerts
        }
        # return the cert password
        return [PSCustomObject]@{
            CertPath = $CertPath
            CertPassword = $CertPassword
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
