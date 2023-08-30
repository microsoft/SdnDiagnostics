function Connect-SlbManager {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [System.String]$SlbManagerPrimary = $env:COMPUTERNAME
    )

    if (Test-ComputerNameIsLocal -ComputerName $SlbManagerPrimary) {
        $useLoopback = $true
    }

    $slbClient = Get-SlbClient -ErrorAction Stop
    if ($null -ieq $slbClient) {
        throw "Unable to connect to SlbClient"
    }

    # if we have already detected that we are using the loopback address, then we can just use that
    # otherwise we will test to check if the SlbManagerPrimary is an IP address or a hostname
    # if it is a hostname, then we will resolve it to an IP address
    if ($useLoopback) {
        $ipAddress = [System.Net.IPAddress]::Loopback
    }
    else {
        $isIpAddress = ($SlbManagerPrimary -as [IPAddress]) -as [Bool]
        if (!$isIpAddress) {
            [IPAddress]$ipAddress = [System.Net.Dns]::GetHostAddresses($SlbManagerPrimary)[0].IPAddressToString
            "Resolved {0} to {1}" -f $SlbManagerPrimary, $ipAddress.IPAddressToString | Trace-Output -Level:Verbose
        }
        else {
            [IPAddress]$ipAddress = $SlbManagerPrimary
        }
    }

    # create IPEndPoint object for the SlbManagerPrimary address and port 49001
    $endpoint = New-Object System.Net.IPEndPoint($ipAddress, 49001)
    $networkControllerNode = Get-SdnNetworkControllerNode -Name $env:COMPUTERNAME

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
