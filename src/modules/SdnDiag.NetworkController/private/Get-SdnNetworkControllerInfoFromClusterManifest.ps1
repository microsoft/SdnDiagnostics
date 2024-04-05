function Get-SdnNetworkControllerInfoFromClusterManifest {
    <#
    .SYNOPSIS
        Get the Network Controller Configuration from network controller cluster manifest file. The function is used to retrieve information of the network controller when cluster down.
    .PARAMETER NetworkController
        Specifies the name the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]$NetworkController = $(HostName),

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    "Attempting to retrieve NetworkController information via ClusterManifest" | Trace-Output

    $clusterManifestXml = [xml](Get-SdnServiceFabricClusterManifest -NetworkController $NetworkController -Credential $Credential)
    $nodeList = $clusterManifestXml.ClusterManifest.Infrastructure.WindowsServer.NodeList.Node.NodeName
    $secretCertThumbprint = $clusterManifestXml.ClusterManifest.Certificates.SecretsCertificate.X509FindValue

    $splat = @{
        Path = 'Cert:\LocalMachine\My'
        Thumbprint = $secretCertThumbprint
    }

    if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
        $serverCertificate = Get-SdnCertificate @splat
    }
    else {
        $serverCertificate = Invoke-PSRemoteCommand -ComputerName $NetworkController -Credential $Credential -ScriptBlock {
            param([Parameter(Position = 0)][String]$param1, [Parameter(Position = 1)][String]$param2)
            Get-SdnCertificate -Path $param1 -Thumbprint $param2
        } -ArgumentList @($splat.Path, $splat.Thumbprint)
    }

    $infraInfo = [PSCustomObject]@{
        Node = $nodeList
        ClientAuthentication = $null
        ClientCertificateThumbprint = $null
        ClientSecurityGroup = $null
        ServerCertificate = $serverCertificate
        RestIPAddress = $null
        RestName = $null
        Version = $null
    }

    return $infraInfo
}
