function Test-MuxBgpConnectionState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricHealthObject]$SdnEnvironmentObject,

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

    $netConnectionExistsScriptBlock = {
        param([Parameter(Position = 0)][String]$arg0)
        $tcpConnection = Get-NetTCPConnection -RemotePort 179 -RemoteAddress $arg0 -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Established" }
        if ($tcpConnection) {
            return $true
        }
    }

    try {
        "Validating the BGP connectivity between the MUX(es) and the top of rack switches." | Trace-Output
        $loadBalancerMux = Get-SdnLoadBalancerMux -NcUri $SdnEnvironmentObject.NcUrl.AbsoluteUri -Credential $NcRestCredential

        # if no load balancer muxes configured within the environment, return back the health object to caller
        if ($null -ieq $loadBalancerMux) {
            return $sdnHealthObject
        }

        # enumerate through the load balancer muxes in the environment and validate the BGP connection state
        foreach ($mux in $loadBalancerMux) {
            $virtualServer = Get-SdnResource -NcUri $SdnEnvironmentObject.NcUrl.AbsoluteUri -Resource $mux.properties.virtualServer.resourceRef -Credential $NcRestCredential
            $virtualServerConnection = $virtualServer.properties.connections[0].managementAddresses
            $peerRouters = $mux.properties.routerConfiguration.peerRouterConfigurations.routerIPAddress
            foreach ($router in $peerRouters) {
                $connectionExists = Invoke-PSRemoteCommand -ComputerName $virtualServerConnection -Credential $Credential -ScriptBlock $netConnectionExistsScriptBlock -ArgumentList $peerRouters
                if (-NOT $connectionExists) {
                    "{0} is not connected to {1}" -f $virtualServerConnection, $router | Trace-Output -Level:Warning
                    $sdnHealthObject.Result = 'FAIL'

                    $object = [PSCustomObject]@{
                        LoadBalancerMux = $virtualServerConnection
                        TopOfRackSwitch = $router
                    }

                    $sdnHealthObject.Properties += $object
                }
            }
        }

        return $sdnHealthObject
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
