function New-SdnNetworkControllerNodeCertificate {
    <#
    .SYNOPSIS
        Generate new Self-Signed Certificate to be used by Network Controller node.
    .PARAMETER NotAfter
        Specifies the date and time, as a DateTime object, that the certificate expires. To obtain a DateTime object, use the Get-Date cmdlet. The default value for this parameter is one year after the certificate was created.
    .PARAMETER CertPassword
        Specifies the password for the exported PFX file in the form of a secure string.
    .PARAMETER Credential
    .EXAMPLE
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [datetime]$NotAfter = (Get-Date).AddYears(1),

        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$CertPassword,

        [Parameter(Mandatory = $false)]
        [System.String]$Path = "$(Get-WorkingDirectory)\Cert_{0}" -f (Get-FormattedDateTimeUTC),

        [Parameter(Mandatory = $false)]
        [System.Object]$FabricDetails,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $config = Get-SdnModuleConfiguration -Role 'NetworkController'
    $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
    if (-NOT ($confirmFeatures)) {
        throw New-Object System.NotSupportedException("The current machine is not a NetworkController, run this on NetworkController.")
    }

    # ensure that the module is running as local administrator
    Confirm-IsAdmin

    try {
        if ($null -eq $FabricDetails) {
            $FabricDetails = [SdnFabricInfrastructure]@{
                NetworkController = (Get-SdnNetworkControllerNode).Server
            }
        }

        if (-NOT (Test-Path -Path $Path -PathType Container)) {
            "Creating directory {0}" -f $Path | Trace-Output
            $CertPath = New-Item -Path $Path -ItemType Directory -Force
        }
        else {
            $CertPath = Get-Item -Path $Path
        }

        $nodeCertSubject = (Get-SdnNetworkControllerNodeCertificate).Subject
        $certificate = New-SdnCertificate -Subject $nodeCertSubject -NotAfter $NotAfter

        # after the certificate has been generated, we want to export the certificate using the $CertPassword provided by the operator
        # and save the file to directory. This allows the rest of the function to pick up these files and perform the steps as normal
        [System.String]$pfxFilePath = "$(Join-Path -Path $CertPath.FullName -ChildPath $nodeCertSubject.ToString().ToLower().Replace('.','_').Replace("=",'_').Trim()).pfx"
        "Exporting pfx certificate to {0}" -f $pfxFilePath | Trace-Output
        $exportedCertificate = Export-PfxCertificate -Cert $certificate -FilePath $pfxFilePath -Password $CertPassword -CryptoAlgorithmOption AES256_SHA256
        $null = Import-SdnCertificate -FilePath $exportedCertificate.FullName -CertStore 'Cert:\LocalMachine\Root' -CertPassword $CertPassword

        Copy-CertificateToFabric -CertFile $exportedCertificate.FullName -CertPassword $CertPassword -FabricDetails $FabricDetails `
            -NetworkControllerNodeCert -Credential $Credential

        return ([PSCustomObject]@{
            Certificate = $certificate
            FileInfo = $exportedCertificate
        })
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
