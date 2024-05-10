
function Get-NetworkControllerNodeInfoFromClusterManifest {
    <#
    .SYNOPSIS
        This function is used as fallback method in the event that normal Get-NetworkControllerNode cmdlet fails in scenarios where certs may be expired
    .PARAMETER NetworkController
        Specifies the Network Controller to retrieve the information from.
    .PARAMETER Name
        Specifies the friendly name of the node for the network controller. If not provided, settings are retrieved for all nodes in the deployment.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]$NetworkController = $(HostName),

        [Parameter(Mandatory = $false)]
        [String]$Name,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    "Attempting to retrieve NetworkControllerNode information via ClusterManifest" | Trace-Output
    $array = @()

    $clusterManifest = [xml](Get-SdnServiceFabricClusterManifest -NetworkController $NetworkController -Credential $Credential)
    $clusterManifest.ClusterManifest.Infrastructure.WindowsServer.NodeList.Node | ForEach-Object {
        $object = [PSCustomObject]@{
            Name = $_.NodeName
            Server = $_.IPAddressOrFQDN
            FaultDomain = $_.FaultDomain
            RestInterface = $null
            Status = $null
            NodeCertificate = $null
        }

	    $certificate = ($clusterManifest.ClusterManifest.NodeTypes.NodeType | Where-Object Name -ieq $_.NodeName).Certificates.ServerCertificate.X509FindValue.ToString()
        $object | Add-Member -MemberType NoteProperty -Name NodeCertificateThumbprint -Value $certificate

        $array += $object
    }

    if ($Name) {
        return ($array | Where-Object { $_.Name.Split(".")[0] -ieq $Name.Split(".")[0] -or $_.Server -ieq $Name.Split(".")[0] })
    }

    return $array
}
