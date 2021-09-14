function Get-PublicIpReference {
    <##>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [uri]$NcUri,

        [Parameter(Mandatory = $true)]
        [System.Object]$IpConfiguration,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {

        # NIC is directly connected to a Public IP
        if($IpConfiguration.properties.publicIPAddress){
            "Located public IP address attached to {0}" -f $IpConfiguration.resourceRef | Trace-Output -Level:Verbose
            return ($IpConfiguration.properties.publicIPAddress.resourceRef)
        }

        # NIC is connected to a load balancer with public IP association
        # or NIC is not associated to a public IP by any means and instead is connected via implicit load balancer attached
        # to a virtual network
        if($IpConfiguration.properties.loadBalancerBackendAddressPools){
            "Located backend address pool association for {0}" -f $IpConfiguration.resourceRef | Trace-Output -Level:Verbose
            $loadBalancers = Get-SdnResource -NcUri $NcUri.AbsoluteUri -ResourceType:LoadBalancers -Credential $Credential
            $allBackendPoolRefs = @($IpConfiguration.properties.loadBalancerBackendAddressPools.resourceRef)
        
            $backendHash = [System.Collections.Hashtable]::new()
            foreach($group in $loadBalancers.properties.backendAddressPools | Group-Object resourceRef){
                [void]$backendHash.Add($group.Name, $group.Group)
            }

            foreach($backendPoolRef in $allBackendPoolRefs){
                $bePool = $backendHash[$backendPoolRef]
        
                if($bePool.properties.outboundNatRules){
                    "Located outbound NAT rule associated with {0}" -f $bePool.resourceRef | Trace-Output -Level:Verbose

                    $obRuleRef = $bePool.properties.outboundNatRules[0].resourceRef
                    break
                }
            }
        
            if($obRuleRef){
                $natRule = $loadBalancers.properties.outboundNatRules | Where-Object {$_.resourceRef -eq $obRuleRef}
                $frontendConfig = $loadBalancers.properties.frontendIPConfigurations | Where-Object {$_.resourceRef -eq $natRule.properties.frontendIPConfigurations[0].resourceRef}

                "Located {0} associated with outbound NAT rule {0}" -f $frontendConfig.resourceRef, $natRule.resourceRef | Trace-Output -Level:Verbose
                return ($frontendConfig.properties.publicIPAddress.resourceRef)
            }
        }

        return $null
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}