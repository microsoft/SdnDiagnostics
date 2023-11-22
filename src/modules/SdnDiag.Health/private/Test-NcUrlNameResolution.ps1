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
        $ncApiReplicaPrimary = Get-SdnServiceFabricReplica -NetworkController $SdnEnvironmentObject.ComputerName -Credential $credential -ServiceTypeName 'ApiService' -Primary
        if ($null -eq $ncApiReplicaPrimary) {
            "Unable to find the primary replica for the ApiService" | Trace-Output -Level:Warning
            return $sdnHealthObject
        }

        $nbApiName = $SdnEnvironmentObject.NcUrl.AbsoluteUri.Split('/')[2]
        $ncNodeName = $ncApiReplicaPrimary.ReplicaAddress.Split(':')[0]

        if ($ncNodeName -is [System.Net.IPAddress]) {
            $ncNodeIp = $ncNodeName.ToString()
        }
        else {
            $ncNodeIp = Resolve-DnsName -Name $ncNodeName -NoHostsFile -ErrorAction SilentlyContinue
            if ($null -ieq $ncNodeIp) {
                "Unable to resolve IP address for {0}" -f $ncNodeName | Trace-Output -Level:Warning
                return $sdnHealthObject
            }
        }

        "ApiService replica primary is hosted on {0} with an IP address of {1}" -f $ncApiReplicaPrimary.ReplicaAddress, $ncNodeIp | Trace-Output
        $dnsResult = Resolve-DnsName -Name $nbApiName -NoHostsFile -ErrorAction SilentlyContinue
        if ($null -ieq $dnsResult) {
            $sdnHealthObject.Result = 'FAIL'

            "Unable to resolve DNS name for {0}" -f $nbApiName | Trace-Output -Level:Warning
            return $sdnHealthObject
        }
        elseif ($dnsResult[0].IPAddress -ine $ncNodeIp) {
            $sdnHealthObject.Result = 'FAIL'
            $sdnHealthObject.Remediation = 'Ensure that the DNS name for the Network Controller NB API URL resolves to the correct IP address.'

            "DNS name for {0} resolves to {1} instead of {2}" -f $nbApiName, $dnsResult[0].IPAddress, $ncNodeIp | Trace-Output -Level:Warning
            return $sdnHealthObject
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
