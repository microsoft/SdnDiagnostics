function Get-SdnPublicIPPoolUsageSummary {
    <#
    .SYNOPSIS
        Returns back the IP addresses associated with the public logical subnet IP pools within the Network Controller environment.
    .DESCRIPTION
        This function returns back a list of IP addresses that are consumed by the PublicIPAddresses and LoadBalancer resources that are derived from the public IP pools.
        This helps operators quickly locate which resources are associated with a public IP address, in addition to identify available vs non-available IP addresses.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate
    )

    $array = @()
    $ncRestParams = @{
        NcUri = $NcUri
    }
    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $ncRestParams.Add('NcRestCredential', $NcRestCredential)
        }
    }

    try {
        $logicalNetworks = Get-SdnResource -Resource LogicalNetworks @ncRestParams | Where-Object {$_.properties.subnets.properties.isPublic -ieq $true}
        $loadBalancers = Get-SdnResource -Resource LoadBalancers @ncRestParams
        $publicIpAddresses = Get-SdnResource -Resource PublicIPAddresses @ncRestParams

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
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
