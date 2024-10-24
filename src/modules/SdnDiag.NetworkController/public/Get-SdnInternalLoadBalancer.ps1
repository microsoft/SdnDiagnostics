function Get-SdnInternalLoadBalancer {
    <#
    .SYNOPSIS
        Performs lookups and joins between OVSDB resources, load balancers and virtual networks to create internal load balancer object mappings
    .PARAMETER NcUri
        Specifies the Network Controller URI to connect to.
    .PARAMETER IPAddress
        Specify the private IP address of the Internal Load Balancer.
    .PARAMETER ProviderAddress
        Specify the provider address IP that is associated with the Internal Load Balancer.
    .PARAMETER Credential
        Specifies a user account that has permission to the Hyper-V Hosts within the SDN Fabric. The default is the current user.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    .EXAMPLE
        Get-SdnInternalLoadBalancer -NcUri https://nc.contoso.com -IPAddress 10.10.0.50
    .EXAMPLE
        Get-SdnInternalLoadBalancer -NcUri https://nc.contoso.com -NcRestCredential (Get-Credential)
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $true, ParameterSetName = 'IPAddress')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ProviderAddress')]
        [Uri]$NcUri,

        [Parameter(Mandatory = $true, ParameterSetName = 'IPAddress')]
        [IPAddress]$IPAddress,

        [Parameter(Mandatory = $true, ParameterSetName = 'ProviderAddress')]
        [IPAddress]$ProviderAddress,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'IPAddress')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ProviderAddress')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'IPAddress')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ProviderAddress')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'IPAddress')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ProviderAddress')]
        [X509Certificate]$NcRestCertificate
    )

    $array = @()
    $subnetHash = [System.Collections.Hashtable]::new()
    $frontendHash = [System.Collections.Hashtable]::new()

    $ncRestParams = @{
        NcUri = $NcUri
    }
    if ($PSBoundParameters.ContainsKey('NcRestCertificate')) {
        $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
    }
    else {
        $ncRestParams.Add('NcRestCredential', $NcRestCredential)
    }

    try {
        $servers = Get-SdnServer @ncRestParams -ManagementAddressOnly

        # if this returns null, this is due to no tenant internal load balancers have been provisioned on the system
        # in which case all the further processing is not needed
        $ovsdbAddressMappings = Get-SdnOvsdbAddressMapping -ComputerName $servers -Credential $Credential | Where-Object {$_.mappingType -eq 'learning_disabled'}
        if($null -eq $ovsdbAddressMappings){
            return $null
        }

        "Located {0} address mappings from OVSDB" -f $ovsdbAddressMappings.Count | Trace-Output -Level:Verbose
        # create a hash table based on the subnet instanceId contained within the virtual networks
        $virtualNetworks = Get-SdnResource @ncRestParams -Resource VirtualNetworks
        foreach($group in $virtualNetworks.properties.subnets | Group-Object InstanceID){
            [void]$subnetHash.Add($group.Name, $group.Group)
        }

        "Located {0} subnets" -f $subnetHash.Count | Trace-Output -Level:Verbose
        # create a hash table based on the resourceRef of the frontendIPConfigurations within the load balancers
        $loadBalancers = Get-SdnResource @ncRestParams -Resource LoadBalancers
        foreach($group in $loadBalancers.properties.frontendIPConfigurations | Group-Object resourceRef){
            [void]$frontendHash.Add($group.Name, $group.Group)
        }

        "Located {0} frontendIPConfigurations" -f $frontendHash.Count | Trace-Output -Level:Verbose
        foreach($ovsdbObject in $ovsdbAddressMappings){

            # leveraging the routing domain ID taken from the OVSDB objects we need to
            # do a lookup against the virtual network subnets to locate the associated ip configurations
            # once we have the ipconfiguration, we want to enumerate each load balancer to match on the customer ip address
            $tenantSubnet = $subnetHash[$ovsdbObject.RoutingDomainID.Guid]
            if($tenantSubnet){
                $loadBalancerResourceRef = $tenantSubnet.properties.ipConfigurations | Where-Object {$_.ResourceRef -like "/loadBalancers/*"}
                if($loadBalancerResourceRef){
                    foreach($resource in $loadBalancerResourceRef){
                        $internalLoadBalancer = $frontendHash[$resource.resourceRef]

                        # if the customer ip address does not match between load balancer and ovsdb then skip it as
                        # this is not the load balancer you are looking for
                        if($internalLoadBalancer){
                            if($internalLoadBalancer.properties.privateIPAddress -ne $ovsdbObject.CustomerAddress){
                                continue
                            }

                            # create a new object to add to the array list as we now have all the mappings we want
                            $array += [PSCustomObject]@{
                                ResourceRef = [String]$internalLoadBalancer.resourceRef
                                CustomerAddress = [IPAddress]$internalLoadBalancer.properties.privateIPAddress
                                ProviderAddress = [IPAddress]$ovsdbObject.ProviderAddress
                            }
                        }
                        else {
                            "Unable to locate Load Balancer Frontend IP Configuration for {0}" -f $resource.resourceRef | Trace-Output -Level:Warning
                        }
                    }
                }
                else {
                    "Unable to locate any Load Balancer objects within IP configurations for {0}" -f $tenantSubnet.resourceRef  | Trace-Output -Level:Warning
                }
            }
            else {
                "Unable to locate Virtual Network Subnet related to Routing Domain ID {0}" -f $ovsdbObject.RoutingDomainID | Trace-Output -Level:Warning
            }
        }

        if ($IPAddress) {
            return ($array | Where-Object {$_.CustomerAddress -eq $IPAddress})
        }

        if ($ProviderAddress) {
            return ($array | Where-Object {$_.ProviderAddress -eq $ProviderAddress})
        }

        return ($array | Sort-Object CustomerAddress -Unique)
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
