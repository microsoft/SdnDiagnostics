function New-SdnServerCertificate {
    <#
    .SYNOPSIS
        Generate new self-signed certificate to be used by the Hyper-V host and distributes to the Network Controller(s) within the environment.
    .PARAMETER NotAfter
        Specifies the date and time, as a DateTime object, that the certificate expires. To obtain a DateTime object, use the Get-Date cmdlet. The default value for this parameter is one year after the certificate was created.
    .PARAMETER Path
        Specifies the file path location where a .cer file is exported automatically.
    .PARAMETER FabricDetails
        The SDN Fabric details derived from Get-SdnInfrastructureInfo.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user
    .EXAMPLE
        New-SdnServerCertificate -NotAfter (Get-Date).AddYears(1) -FabricDetails $Global:SdnDiagnostics.EnvironmentInfo
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [datetime]$NotAfter = (Get-Date).AddYears(3),

        [Parameter(Mandatory = $false)]
        [System.String]$Path = "$(Get-WorkingDirectory)\ServerCert_{0}" -f (Get-FormattedDateTimeUTC),

        [Parameter(Mandatory = $false)]
        [System.Object]$FabricDetails,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $config = Get-SdnModuleConfiguration -Role 'Server'
    $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
    if (-NOT ($confirmFeatures)) {
        throw New-Object System.NotSupportedException("The current machine is not a Server, run this on Server.")
    }

    # ensure that the module is running as local administrator
    $elevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-NOT $elevated) {
        throw New-Object System.Exception("This function requires elevated permissions. Run PowerShell as an Administrator and import the module again.")
    }

    try {
        if (-NOT (Test-Path -Path $Path -PathType Container)) {
            "Creating directory {0}" -f $Path | Trace-Output
            $CertPath = New-Item -Path $Path -ItemType Directory -Force
        }
        else {
            $CertPath = Get-Item -Path $Path
        }

        $serverCert = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters' -Name 'HostAgentCertificateCName'
        $subjectName = "CN={0}" -f $serverCert
        $certificate = New-SdnCertificate -Subject $subjectName -NotAfter $NotAfter

        # after the certificate has been generated, we want to export the certificate and save the file to directory
        # This allows the rest of the function to pick up these files and perform the steps as normal
        [System.String]$cerFilePath = "$(Join-Path -Path $CertPath.FullName -ChildPath $subjectName.ToString().ToLower().Replace('.','_').Replace("=",'_').Trim()).cer"
        "Exporting certificate to {0}" -f $cerFilePath | Trace-Output
        $exportedCertificate = Export-Certificate -Cert $certificate -FilePath $cerFilePath -Type CERT
        Copy-CertificateToFabric -CertFile $exportedCertificate.FullName -FabricDetails $FabricDetails -ServerNodeCert -Credential $Credential

        $certObject = [PSCustomObject]@{
            Certificate = $certificate
            FileInfo = $exportedCertificate
        }

        return $certObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
