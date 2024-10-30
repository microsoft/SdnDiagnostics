function Test-SlbManagerConnectionToMux {
    <#
    .SYNOPSIS
        Validates the TCP connection between LoadBalancerMuxes and primary replica of SlbManager service within Network Controller.
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate
    )

    $ncRestParams = @{
        NcUri = $SdnEnvironmentObject.NcUrl
    }
    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $ncRestParams.Add('NcRestCredential', $NcRestCredential)
        }
    }

    $sdnHealthObject = [SdnHealth]::new()
    $array = @()

    $netConnectionExistsScriptBlock = {
        $tcpConnection = Get-NetTCPConnection -LocalPort 8560 -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Established" }
        if ($tcpConnection) {
            return $true
        }
    }

    try {
        "Validating connectivity between LoadBalancerMuxes and primary replica of SlbManager service within Network Controller" | Trace-Output
        $loadBalancerMux = Get-SdnLoadBalancerMux @ncRestParams

        # if no load balancer muxes configured within the environment, return back the health object to caller
        if ($null -ieq $loadBalancerMux) {
            return $sdnHealthObject
        }

        # get the current primary replica of Network Controller
        # if we cannot return the primary replica, then something is critically wrong with Network Controller
        # in which case we should mark this test as failed and return back to the caller with guidance to fix the SlbManagerService
        $primaryReplicaNode = Get-SdnServiceFabricReplica -NetworkController $SdnEnvironmentObject.EnvironmentInfo.NetworkController[0] -ServiceTypeName 'SlbManagerService' -Credential $NcRestCredential -Primary
        if ($null -ieq $primaryReplicaNode) {
            "Unable to return primary replica of SlbManagerService" | Trace-Output -Level:Error
            $sdnHealthObject.Result = 'FAIL'
            $sdnHealthObject.Remediation = "Fix the primary replica of SlbManagerService within Network Controller."
            return $sdnHealthObject
        }

        # enumerate through the load balancer muxes in the environment and validate the TCP connection state
        # we expect the primary replica for SlbManager within Network Controller to have an active connection for DIP:VIP programming to the Muxes
        foreach ($mux in $loadBalancerMux) {
            $virtualServer = Get-SdnResource @ncRestParams -ResourceRef $mux.properties.virtualServer.resourceRef
            $virtualServerConnection = $virtualServer.properties.connections[0].managementAddresses
            $connectionExists = Invoke-PSRemoteCommand -ComputerName $virtualServerConnection -Credential $Credential -ScriptBlock $netConnectionExistsScriptBlock
            if (-NOT $connectionExists) {
                "{0} is not connected to SlbManager of Network Controller" -f $mux.resourceRef | Trace-Output -Level:Error
                $sdnHealthObject.Result = 'FAIL'
                $sdnHealthObject.Remediation += "Investigate and fix TCP connectivity or x509 authentication between $($primaryReplicaNode.ReplicaAddress) and $($mux.resourceRef)."

                $object = [PSCustomObject]@{
                    LoadBalancerMux = $mux.resourceRef
                    SlbManagerPrimaryReplica = $primaryReplicaNode.ReplicaAddress
                }

                $array += $object
            }
            else {
                "{0} is connected to {1}" -f $mux.resourceRef, $primaryReplicaNode.ReplicaAddress | Trace-Output -Level:Verbose
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
