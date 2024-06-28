function Get-SdnNetworkControllerInfoOffline {
    <#
    .SYNOPSIS
        Get the Network Controller Configuration from network controller cluster manifest file. The function is used to retrieve information of the network controller when cluster down.
    .PARAMETER NetworkController
        Specifies the name the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnNetworkControllerInfoOffline
    .EXAMPLE
        PS> Get-SdnNetworkControllerInfoOffline -NetworkController 'NC01' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
        Confirm-IsNetworkController
    }

    try {
        $clusterManifestXml = [xml](Get-SdnServiceFabricClusterManifest -NetworkController $NetworkController -Credential $Credential)
        $NodeList = $clusterManifestXml.ClusterManifest.Infrastructure.WindowsServer.NodeList.Node
        $securitySection = $clusterManifestXml.ClusterManifest.FabricSettings.Section | Where-Object Name -eq "Security"
        $ClusterCredentialType = $securitySection.Parameter | Where-Object Name -eq "ClusterCredentialType"
        $secretCertThumbprint = $clusterManifestXml.ClusterManifest.Certificates.SecretsCertificate.X509FindValue

        $ncRestName = Invoke-PSRemoteCommand -ComputerName $NetworkController -Credential $Credential -ScriptBlock {
            param([Parameter(Position = 0)][String]$param1, [Parameter(Position = 1)][String]$param2)
            $secretCert = Get-ChildItem -Path $param1 | Where-Object {$_.Thumbprint -ieq $param2}
            if($null -eq $secretCert) {
                return $null
            }
            else {
                return $secretCert.Subject.Replace("CN=","")
            }
        } -ArgumentList @('Cert:\LocalMachine\My', $secretCertThumbprint)

        $infraInfo = [PSCustomObject]@{
            ClusterCredentialType = $ClusterCredentialType.Value
            NodeList = $NodeList
            NcRestName = $ncRestName
            NcRestCertThumbprint = $secretCertThumbprint
        }

        return $infraInfo
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
