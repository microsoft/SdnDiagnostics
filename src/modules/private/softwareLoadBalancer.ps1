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
            return ($IpConfiguration.properties.publicIPAddress.resourceRef)
        }

        # NIC is connected to a load balancer with public IP association
        # or NIC is not associated to a public IP by any means and instead is connected via implicit load balancer attached
        # to a virtual network
        if($IpConfiguration.properties.loadBalancerBackendAddressPools){
            $loadBalancers = Get-SdnResource -NcUri $NcUri.AbsoluteUri -ResourceType:LoadBalancers -Credential $Credential
            $allBackendPoolRefs = @($IpConfiguration.properties.loadBalancerBackendAddressPools.resourceRef)
        
            $frontendHash = [System.Collections.Hashtable]::new()
            foreach($group in $loadBalancers.properties.frontendIPConfigurations | Group-Object resourceRef){
                [void]$frontendHash.Add($group.Name, $group.Group)
            }
        
            $backendHash = [System.Collections.Hashtable]::new()
            foreach($group in $loadBalancers.properties.BackendAddressPools | Group-Object resourceRef){
                [void]$backendHash.Add($group.Name, $group.Group)
            }

            foreach($backendPoolRef in $allBackendPoolRefs){
                $bePool = $backendHash[$backendPoolRef]
        
                if($bePool.properties.outboundNatRules){
                    $obRuleRef = $loadBalancer.properties.outboundNatRules[0].resourceRef
                    break
                }
            }
        
            if($obRuleRef){
                $frontEnd = $frontendHash[$obRule.properties.frontendIPConfigurations[0].resourceRef]
                return ($frontEnd.properties.publicIPAddress.resourceRef)
            }
        }

        return $null
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}