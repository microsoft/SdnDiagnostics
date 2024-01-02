function Test-MuxBgpConnectionState {
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
        param([Parameter(Position = 0)][String]$arg0)
        $tcpConnection = Get-NetTCPConnection -RemotePort 179 -RemoteAddress $arg0 -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Established" }
        if ($tcpConnection) {
            return $true
        }
    }

    try {
        "Validating the BGP connectivity between LoadBalancerMuxes and Top of Rack (ToR) Switches." | Trace-Output
        $loadBalancerMux = Get-SdnLoadBalancerMux -NcUri $SdnEnvironmentObject.NcUrl.AbsoluteUri -Credential $NcRestCredential

        # if no load balancer muxes configured within the environment, return back the health object to caller
        if ($null -ieq $loadBalancerMux) {
            return $sdnHealthObject
        }

        # enumerate through the load balancer muxes in the environment and validate the BGP connection state
        foreach ($mux in $loadBalancerMux) {
            $virtualServer = Get-SdnResource -NcUri $SdnEnvironmentObject.NcUrl.AbsoluteUri -ResourceRef $mux.properties.virtualServer.resourceRef -Credential $NcRestCredential
            [string]$virtualServerConnection = $virtualServer.properties.connections[0].managementAddresses
            $peerRouters = $mux.properties.routerConfiguration.peerRouterConfigurations.routerIPAddress
            foreach ($router in $peerRouters) {
                $connectionExists = Invoke-PSRemoteCommand -ComputerName $virtualServerConnection -Credential $Credential -ScriptBlock $netConnectionExistsScriptBlock -ArgumentList $router
                if (-NOT $connectionExists) {
                    "{0} is not connected to {1}" -f $virtualServerConnection, $router | Trace-Output -Level:Error
                    $sdnHealthObject.Result = 'FAIL'
                    $sdnHealthObject.Remediation += "Fix BGP Peering between $($virtualServerConnection) and $($router)."

                    # create a custom object to store the load balancer mux and the router that it is not connected to
                    # this will be added to the array
                    $object = [PSCustomObject]@{
                        LoadBalancerMux = $virtualServerConnection
                        TopOfRackSwitch = $router
                    }

                    $array += $object
                }
                else {
                    "{0} is connected to {1}" -f $virtualServerConnection, $router | Trace-Output -Level:Verbose
                }
            }
        }

        # if the array is not empty, add it to the health object
        if ($array) {
            $sdnHealthObject.Properties = $array
        }

        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
    }
}
