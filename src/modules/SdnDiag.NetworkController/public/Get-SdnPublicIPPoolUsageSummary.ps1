function Get-SdnPublicIPPoolUsageSummary {
    <#
    .SYNOPSIS
        Returns back the IP addresses associated with the public logical subnet IP pools within the Network Controller environment.
    .DESCRIPTION
        This function returns back a list of IP addresses that are consumed by the PublicIPAddresses and LoadBalancer resources that are derived from the public IP pools.
        This helps operators quickly locate which resources are associated with a public IP address, in addition to identify available vs non-available IP addresses.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    $array = @()

    try {
        $logicalNetworks = Get-SdnResource -NcUri $NcUri -Resource LogicalNetworks -Credential $NcRestCredential | Where-Object {$_.properties.subnets.properties.isPublic -ieq $true}
        $loadBalancers = Get-SdnResource -NcUri $NcUri -Resource LoadBalancers -Credential $NcRestCredential
        $publicIpAddresses = Get-SdnResource -NcUri $NcUri -Resource PublicIPAddresses -Credential $NcRestCredential

        foreach ($subnet in $logicalNetworks.properties.subnets) {
            foreach ($ipPool in $subnet.properties.ipPools) {
                # check to see if there was any loadbalancer frontend resources on the system and cross compare with the logical subnet ipPool
                # if they address falls within the ipPool range, then add to the array
                if ($loadBalancers) {
                    foreach ($loadBalancer in $loadBalancers) {
                        foreach ($frontEndConfig in $loadBalancer.properties.frontendIPConfigurations) {
                            if ($frontEndConfig.properties.privateIPAddress) {
                                if (Confirm-IpAddressInRange -IpAddress $frontEndConfig.properties.privateIPAddress -StartAddress $ipPool.properties.startIpAddress -EndAddress $ipPool.properties.EndIpAddress) {

                                    $object = [PSCustomObject]@{
                                        IPPool = $ipPool.ResourceId
                                        IPAddress = $frontEndConfig.properties.privateIPAddress
                                        ProvisioningState = $frontEndConfig.properties.provisioningState
                                        AllocationMethod = $frontEndConfig.properties.privateIPAllocationMethod
                                        ResourceType = 'FrontEndIpConfiguration'
                                        ResourceId = $frontEndConfig.resourceId
                                        InstanceId = $frontEndConfig.instanceId
                                        AssociatedResource = $loadBalancer.resourceRef
                                    }

                                    $array += $object
                                }
                            }
                        }
                    }
                }

                # check to see if there was any public IP address resources on the system and cross compare with the logical subnet ipPool
                # if they address falls within the ipPool range, then add to the array
                if ($publicIpAddresses) {
                    foreach ($publicIp in $publicIpAddresses) {
                        if (Confirm-IpAddressInRange -IpAddress $publicIp.properties.IpAddress -StartAddress $ipPool.properties.startIpAddress -EndAddress $ipPool.properties.EndIpAddress) {

                            $object = [PSCustomObject]@{
                                IPPool = $ipPool.ResourceId
                                IPAddress = $publicIp.properties.ipAddress
                                ProvisioningState = $publicIp.properties.provisioningState
                                AllocationMethod = $publicIp.properties.publicIPAllocationMethod
                                ResourceType = 'PublicIpAddress'
                                ResourceId = $publicIp.resourceId
                                InstanceId = $publicIp.instanceId
                                AssociatedResource = $publicIp.properties.ipConfiguration.resourceRef
                            }

                            $array += $object
                        }
                    }
                }
            }
        }

        return ($array | Sort-Object -Property 'IpAddress')
    }
    catch {
       $_ | Trace-Output -Level:Error
    }
}
