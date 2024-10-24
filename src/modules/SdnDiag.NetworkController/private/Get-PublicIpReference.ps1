function Get-PublicIpReference {
    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [uri]$NcUri,

        [Parameter(Mandatory = $true)]
        [System.Object]$IpConfiguration,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    $restParams = @{
        NcUri = $NcUri
    }
    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $restParams.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $restParams.Add('NcRestCredential', $NcRestCredential)
        }
    }

    try {
        # check for an instance-level public IP address that is directly associated
        # with the ipconfiguration and return back to calling function
        if ($IpConfiguration.properties.publicIPAddress) {
            "Located {0} associated with {1}" -f $IpConfiguration.properties.publicIPAddress.resourceRef, $IpConfiguration.resourceRef | Trace-Output -Level:Verbose
            return ($IpConfiguration.properties.publicIPAddress.resourceRef)
        }
        else {
            "Unable to locate an instance-level public IP address associated with {0}" -f $IpConfiguration.resourceRef | Trace-Output -Level:Verbose
        }

        # NIC is connected to a load balancer with public IP association
        # or NIC is not associated to a public IP by any means and instead is connected via implicit load balancer attached to a virtual network
        "Checking for any backend address pool associated with {0}" -f $IpConfiguration.resourceRef | Trace-Output -Level:Verbose
        if ($IpConfiguration.properties.loadBalancerBackendAddressPools) {
            "Located backend address pool associations for {0}" -f $IpConfiguration.resourceRef | Trace-Output -Level:Verbose
            $allBackendPoolRefs = @($IpConfiguration.properties.loadBalancerBackendAddressPools.resourceRef)

            $loadBalancers = Get-SdnResource -Resource:LoadBalancers @restParams
            $backendHash = [System.Collections.Hashtable]::new()
            foreach ($group in $loadBalancers.properties.backendAddressPools | Group-Object resourceRef) {
                [void]$backendHash.Add($group.Name, $group.Group)
            }

            foreach ($backendPoolRef in $allBackendPoolRefs) {
                "Checking for outboundNatRules for {0}" -f $backendPoolRef | Trace-Output -Level:Verbose
                $bePool = $backendHash[$backendPoolRef]

                if ($bePool.properties.outboundNatRules) {
                    "Located outboundNatRule associated with {0}" -f $bePool.resourceRef | Trace-Output -Level:Verbose

                    $obRuleRef = $bePool.properties.outboundNatRules[0].resourceRef
                    break
                }
            }

            if ($obRuleRef) {
                $natRule = $loadBalancers.properties.outboundNatRules | Where-Object { $_.resourceRef -eq $obRuleRef }
                $frontendConfig = $loadBalancers.properties.frontendIPConfigurations | Where-Object { $_.resourceRef -eq $natRule.properties.frontendIPConfigurations[0].resourceRef }

                "Located {0} associated with {0}" -f $frontendConfig.resourceRef, $natRule.resourceRef | Trace-Output -Level:Verbose
                return ($frontendConfig.properties.publicIPAddress.resourceRef)
            }
            else {
                "Unable to locate outboundNatRules associated with {0}" -f $IpConfiguration.properties.loadBalancerBackendAddressPools.resourceRef | Trace-Output -Level:Verbose
            }
        }
        else {
            "Unable to locate any backend pools associated with {0}" -f $IpConfiguration.resourceRef | Trace-Output -Level:Verbose
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }

    return $null
}
