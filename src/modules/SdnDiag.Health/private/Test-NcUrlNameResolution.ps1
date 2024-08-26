function Test-NcUrlNameResolution {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()

    try {
        "Validate that the Network Controller NB API URL resolves to the correct IP address" | Trace-Output

        $ncApiReplicaPrimary = Get-SdnServiceFabricReplica -NetworkController $SdnEnvironmentObject.ComputerName[0] -Credential $Credential -ServiceTypeName 'ApiService' -Primary
        if ($null -eq $ncApiReplicaPrimary) {
            "Unable to find the primary replica for the ApiService" | Trace-Output -Level:Warning
            return $sdnHealthObject
        }

        $networkController = Get-SdnNetworkController -NetworkController $SdnEnvironmentObject.ComputerName[0] -Credential $Credential
        if ($null -eq $networkController) {
            "Unable to retrieve results from Get-SdnNetworkController" | Trace-Output -Level:Warning
            return $sdnHealthObject
        }

        # depending on the configuration returned, will determine if we need to use the RestIPAddress or RestName
        $nbApiName = $networkController.ServerCertificate.Subject.Split('=')[1].Trim()

        if ($networkController.RestIPAddress) {
            $expectedIPAddress = $($networkController.RestIPAddress).Split('/')[0].Trim() # we expect to be in IP/CIDR format
            "Network Controller is configured with static RestIPAddress: {0}" -f $expectedIPAddress | Trace-Output -Level:Verbose
        }
        else {
            "Network Controller is configured with RestName" | Trace-Output -Level:Verbose
            $ncNodeName = $ncApiReplicaPrimary.ReplicaAddress.Split(':')[0].Trim()
            $isIpAddress = [System.Net.IPAddress]::TryParse($ncNodeName, [ref]$null)
            if ($isIpAddress) {
                $expectedIPAddress = $ncNodeName.ToString()
            }
            else {
                $dnsResultNetworkControllerNode = Resolve-DnsName -Name $ncNodeName -NoHostsFile -ErrorAction SilentlyContinue
                if ($null -ieq $dnsResultNetworkControllerNode) {
                    "Unable to resolve IP address for {0}" -f $ncNodeName | Trace-Output -Level:Warning
                    return $sdnHealthObject
                }
                else {
                    $expectedIPAddress = $dnsResultNetworkControllerNode.IPAddress
                    "ApiService replica primary is hosted on {0} with an IP address of {1}" -f $ncApiReplicaPrimary.ReplicaAddress, $expectedIPAddress | Trace-Output -Level:Verbose
                }
            }
        }

        # in this scenario, the certificate is using an IP address as the subject, so we will need to compare the IP address to the expected IP address
        # if they match, we will return a success
        $isIpAddress = [System.Net.IPAddress]::TryParse($nbApiName, [ref]$null)
        if ($isIpAddress -and ($nbApiName -ieq $expectedIPAddress)) {
            return $sdnHealthObject
        }

        # perform some DNS resolution to ensure that the NB API URL resolves to the correct IP address
        $dnsResult = Resolve-DnsName -Name $nbApiName -NoHostsFile -ErrorAction SilentlyContinue
        if ($null -ieq $dnsResult) {
            $sdnHealthObject.Result = 'FAIL'

            "Unable to resolve DNS name for {0}" -f $nbApiName | Trace-Output -Level:Warning
            return $sdnHealthObject
        }
        elseif ($dnsResult[0].IPAddress -ine $expectedIPAddress) {
            $sdnHealthObject.Result = 'FAIL'
            $sdnHealthObject.Remediation = 'Ensure that the DNS name for the Network Controller NB API URL resolves to the correct IP address.'

            "DNS name for {0} resolves to {1} instead of {2}" -f $nbApiName, $dnsResult[0].IPAddress, $expectedIPAddress | Trace-Output -Level:Warning
            return $sdnHealthObject
        }

        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
