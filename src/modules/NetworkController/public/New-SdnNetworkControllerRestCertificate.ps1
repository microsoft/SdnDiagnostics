# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function New-SdnNetworkControllerRestCertificate {
    <#
    .SYNOPSIS
        Generate new Self-Signed Certificate to be used by Network Controller.
    .PARAMETER NotAfter
        Specifies the date and time, as a DateTime object, that the certificate expires. To obtain a DateTime object, use the Get-Date cmdlet. The default value for this parameter is one year after the certificate was created.
    .PARAMETER CertPassword
        Specifies the password for the imported PFX file in the form of a secure string.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$RestName,

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

    $config = Get-SdnRoleConfiguration -Role 'NetworkController'
    $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
    if (-NOT ($confirmFeatures)) {
        throw New-Object System.NotSupportedException("The current machine is not a NetworkController, run this on NetworkController.")
    }

    # ensure that the module is running as local administrator
    $elevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-NOT $elevated) {
        throw New-Object System.Exception("This function requires elevated permissions. Run PowerShell as an Administrator and import the module again.")
    }

    try {
        if ($FabricDetails) {
            if ($null -ne $FabricDetails.SoftwareLoadBalancer -or $null -ne $FabricDetails.Server) {
                $installToSouthboundDevices = $true
            }
            else {
                $installToSouthboundDevices = $false
            }
        }
        else {
            $installToSouthboundDevices = $false

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

        [System.String]$formattedSubject = "CN={0}" -f $RestName.Trim()
        $certificate = New-SdnCertificate -Subject $formattedSubject -NotAfter $NotAfter

        # after the certificate has been generated, we want to export the certificate using the $CertPassword provided by the operator
        # and save the file to directory. This allows the rest of the function to pick up these files and perform the steps as normal
        [System.String]$pfxFilePath = "$(Join-Path -Path $CertPath.FullName -ChildPath $RestName.ToLower().Replace('.','_').Replace('=','_').Trim()).pfx"
        "Exporting pfx certificate to {0}" -f $pfxFilePath | Trace-Output
        $exportedCertificate = Export-PfxCertificate -Cert $certificate -FilePath $pfxFilePath -Password $CertPassword -CryptoAlgorithmOption AES256_SHA256
        $null = Import-SdnCertificate -FilePath $exportedCertificate.FullName -CertStore 'Cert:\LocalMachine\Root' -CertPassword $CertPassword

        Copy-CertificateToFabric -CertFile $exportedCertificate.FullName -CertPassword $CertPassword -FabricDetails $FabricDetails `
            -NetworkControllerRestCertificate -InstallToSouthboundDevices:$installToSouthboundDevices -Credential $Credential

        return ([PSCustomObject]@{
            Certificate = $certificate
            FileInfo = $exportedCertificate
        })
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
