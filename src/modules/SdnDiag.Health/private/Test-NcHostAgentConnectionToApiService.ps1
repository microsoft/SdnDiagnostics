function Test-NcHostAgentConnectionToApiService {
    <#
    .SYNOPSIS
        Validates the TCP connection between Server and primary replica of Api service within Network Controller.
    #>

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
    $array = @()

    $netConnectionExistsScriptBlock = {
        $tcpConnection = Get-NetTCPConnection -RemotePort 6640 -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Established" }
        if ($tcpConnection) {
            return $true
        }
    }

    try {
        "Validating connectivity between Server and primary replica of API service within Network Controller" | Trace-Output
        $servers = Get-SdnServer -NcUri $SdnEnvironmentObject.NcUrl.AbsoluteUri -Credential $NcRestCredential

        # if no load balancer muxes configured within the environment, return back the health object to caller
        if ($null -ieq $servers) {
            return $sdnHealthObject
        }

        # get the current primary replica of Network Controller
        # if we cannot return the primary replica, then something is critically wrong with Network Controller
        # in which case we should mark this test as failed and return back to the caller with guidance to fix the SlbManagerService
        $primaryReplicaNode = Get-SdnServiceFabricReplica -NetworkController $SdnEnvironmentObject.EnvironmentInfo.NetworkController[0] -ServiceTypeName 'ApiService' -Credential $Credential -Primary
        if ($null -ieq $primaryReplicaNode) {
            "Unable to return primary replica of ApiService" | Trace-Output -Level:Error
            $sdnHealthObject.Result = 'FAIL'
            $sdnHealthObject.Remediation = "Fix the primary replica of ApiService within Network Controller."
            return $sdnHealthObject
        }

        # enumerate through the servers in the environment and validate the TCP connection state
        # we expect the NCHostAgent to have an active connection to ApiService within Network Controller via port 6640, which informs
        # Network Controller that the host is operational and ready to receive policy configuration updates
        foreach ($server in $servers) {
            [System.Array]$connectionAddress = Get-SdnServer -NcUri $SdnEnvironmentObject.NcUrl.AbsoluteUri -ResourceId $server.resourceId -ManagementAddressOnly -Credential $NcRestCredential
            $connectionExists = Invoke-PSRemoteCommand -ComputerName $connectionAddress[0] -Credential $Credential -ScriptBlock $netConnectionExistsScriptBlock
            if (-NOT $connectionExists) {
                "{0} is not connected to ApiService of Network Controller" -f $server.resourceRef | Trace-Output -Level:Error
                $sdnHealthObject.Result = 'FAIL'
                $sdnHealthObject.Remediation += "Ensure NCHostAgent service is started. Investigate and fix TCP connectivity or x509 authentication between $($primaryReplicaNode.ReplicaAddress) and $($server.resourceRef)."

                $object = [PSCustomObject]@{
                    Server = $server.resourceRef
                    ApiPrimaryReplica = $primaryReplicaNode.ReplicaAddress
                }

                $array += $object
            }
            else {
                "{0} is connected to {1}" -f $server.resourceRef, $primaryReplicaNode.ReplicaAddress | Trace-Output -Level:Verbose
            }
        }

        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
