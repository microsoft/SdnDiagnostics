function Connect-SlbManager {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $slbClient = Get-SlbClient -ErrorAction Stop

    # we need identify the current primary replica for the slbmanager service
    # if the primary replica is on the local node, then we will use the loopback address
    $slbManagerPrimary = Get-SdnServiceFabricReplica -ServiceTypeName 'SlbManagerService' -Primary -Credential $Credential -ErrorAction Stop
    if ($null -ieq $slbManagerPrimary) {
        throw "Unable to return primary replica of SlbManagerService"
    }

    $slbManagerPrimaryNodeName = $slbManagerPrimary.ReplicaAddress.Split(':')[0]
    if (Test-ComputerNameIsLocal -ComputerName $slbManagerPrimaryNodeName) {
        $useLoopback = $true
    }

    # if we have already detected that we are using the loopback address, then we can just use that
    # otherwise we will test to check if the SlbManagerPrimary is an IP address or a hostname
    # if it is a hostname, then we will resolve it to an IP address
    if ($useLoopback) {
        $ipAddress = [System.Net.IPAddress]::Loopback
    }
    else {
        $isIpAddress = ($slbManagerPrimaryNodeName -as [IPAddress]) -as [Bool]
        if (!$isIpAddress) {
            [IPAddress]$ipAddress = [System.Net.Dns]::GetHostAddresses($slbManagerPrimaryNodeName)[0].IPAddressToString
            "Resolved {0} to {1}" -f $slbManagerPrimaryNodeName, $ipAddress.IPAddressToString | Trace-Output -Level:Verbose
        }
        else {
            [IPAddress]$ipAddress = $slbManagerPrimaryNodeName
        }
    }

    # create IPEndPoint object for the SlbManagerPrimary address and port 49001
    $endpoint = New-Object System.Net.IPEndPoint($ipAddress, 49001)
    $networkControllerNode = Get-SdnNetworkControllerSFNode -Name $env:COMPUTERNAME

    # check to see if we have a node certificate that will be used for establishing connectivity
    # otherwise if not using x509 between the NC nodes we can just use $null
    if ($networkControllerNode.NodeCertificate.Thumbprint) {
        $slbmConnection = $slbClient.ConnectToSlbManager($endpoint, $networkControllerNode.NodeCertificate.Thumbprint, $null)
    }
    else {
        $slbmConnection = $slbClient.ConnectToSlbManager($endpoint, $null, $null)
    }

    return $slbmConnection
}
