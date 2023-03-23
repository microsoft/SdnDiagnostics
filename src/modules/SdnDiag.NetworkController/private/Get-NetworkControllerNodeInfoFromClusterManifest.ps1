
function Get-NetworkControllerNodeInfoFromClusterManifest {
    <#
    .SYNOPSIS
        This function is used as fallback method in the event that normal Get-NetworkControllerNode cmdlet fails in scenarios where certs may be expired
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

    "Attempting to retrieve NetworkControllerNode information via ClusterManifest and other methods" | Trace-Output
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

    return $array
}
