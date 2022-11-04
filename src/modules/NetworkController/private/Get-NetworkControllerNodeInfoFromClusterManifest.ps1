function Get-NetworkControllerNodeInfoFromClusterManifest {
    <#
    .SYNOPSIS
        This function is used as fallback method in the event that normal Get-NetworkControllerNode cmdlet fails in scenarios where certs may be expired
    #>

    [CmdletBinding()]
    param ()

    "Attempting to retrieve NetworkControllerNode information via ClusterManifest and other methods" | Trace-Output

    $clusterManifest = [xml](Get-SdnServiceFabricClusterManifest)
    $currentNodeName = $env:COMPUTERNAME
    $currentIPAddresses = (Get-NetIPAddress).IPAddress

    $currentNode = $clusterManifest.ClusterManifest.Infrastructure.WindowsServer.NodeList.Node `
    | Where-Object {$_.NodeName -ilike "$($currentNodeName).*" -or $_.IPAddressOrFQDN -iin $currentIPAddresses -or $_.IPAddressOrFQDN -ilike "$($currentNodeName).*"}

    $object = [PSCustomObject]@{
        Name = $currentNode.NodeName
        Server = $currentNode.IPAddressOrFQDN
        FaultDomain = $currentNode.FaultDomain
        RestInterface = $null
        Status = $null
    }

    $certificate = ($clusterManifest.ClusterManifest.NodeTypes.NodeType | Where-Object Name -ieq $object.Name).Certificates.ServerCertificate.X509FindValue.ToString()
    $cert = Get-SdnCertificate -Path 'Cert:\LocalMachine\My' -Thumbprint $certificate

    $object | Add-Member -MemberType NoteProperty -Name NodeCertificate -Value $cert

    return $object
}
