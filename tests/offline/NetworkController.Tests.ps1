Describe 'NetworkController - Get-SdnServer' {
    It "Returns server resources with resourceRef populated" {
        InModuleScope SdnDiag.NetworkController {
            Mock Invoke-RestMethodWithRetry {
                $path = ([Uri]$Uri).AbsolutePath
                if ($path -match '/networking/v1/(.+)$') {
                    $resourceType = ($Matches[1] -split '/')[0]
                    return [PSCustomObject]@{ value = $Global:PesterOfflineTests.SdnApiResources[$resourceType] }
                }
            }
            $servers = Get-SdnServer -NcUri "https://dvlab-nc.dvlab.contoso.local"
            $servers.Count | Should -BeGreaterThan 0
            $servers[0].resourceRef | Should -Not -BeNullOrEmpty
        }
    }

    It "Returns management addresses as strings with -ManagementAddressOnly" {
        InModuleScope SdnDiag.NetworkController {
            Mock Invoke-RestMethodWithRetry {
                $path = ([Uri]$Uri).AbsolutePath
                if ($path -match '/networking/v1/(.+)$') {
                    $resourceType = ($Matches[1] -split '/')[0]
                    return [PSCustomObject]@{ value = $Global:PesterOfflineTests.SdnApiResources[$resourceType] }
                }
            }
            $servers = Get-SdnServer -NcUri "https://dvlab-nc.dvlab.contoso.local" -ManagementAddressOnly
            $servers.Count | Should -BeGreaterThan 0
            $servers[0].GetType().Name | Should -Be "String"
        }
    }

    It "Returns all 4 servers from mock data" {
        InModuleScope SdnDiag.NetworkController {
            Mock Invoke-RestMethodWithRetry {
                $path = ([Uri]$Uri).AbsolutePath
                if ($path -match '/networking/v1/(.+)$') {
                    $resourceType = ($Matches[1] -split '/')[0]
                    return [PSCustomObject]@{ value = $Global:PesterOfflineTests.SdnApiResources[$resourceType] }
                }
            }
            $servers = Get-SdnServer -NcUri "https://dvlab-nc.dvlab.contoso.local"
            $servers.Count | Should -Be 4
        }
    }
}

Describe 'NetworkController - Get-SdnGateway' {
    It "Returns gateway resources" {
        InModuleScope SdnDiag.NetworkController {
            Mock Invoke-RestMethodWithRetry {
                $path = ([Uri]$Uri).AbsolutePath
                if ($path -match '/networking/v1/(.+)$') {
                    $resourceType = ($Matches[1] -split '/')[0]
                    return [PSCustomObject]@{ value = $Global:PesterOfflineTests.SdnApiResources[$resourceType] }
                }
            }
            $gateways = Get-SdnGateway -NcUri "https://dvlab-nc.dvlab.contoso.local"
            $gateways.Count | Should -Be 3
            $gateways[0].resourceRef | Should -Not -BeNullOrEmpty
        }
    }

    It "Returns management addresses as strings with -ManagementAddressOnly" {
        InModuleScope SdnDiag.NetworkController {
            Mock Invoke-RestMethodWithRetry {
                $path = ([Uri]$Uri).AbsolutePath
                if ($path -match '/networking/v1/(.+)$') {
                    $resourceType = ($Matches[1] -split '/')[0]
                    $refKey = "/$($Matches[1])"
                    if ($Global:PesterOfflineTests.SdnApiResourcesByRef.ContainsKey($refKey)) {
                        return $Global:PesterOfflineTests.SdnApiResourcesByRef[$refKey]
                    }
                    return [PSCustomObject]@{ value = $Global:PesterOfflineTests.SdnApiResources[$resourceType] }
                }
            }
            $gateways = Get-SdnGateway -NcUri "https://dvlab-nc.dvlab.contoso.local" -ManagementAddressOnly
            $gateways.Count | Should -BeGreaterThan 0
            $gateways[0].GetType().Name | Should -Be "String"
        }
    }
}

Describe 'NetworkController - Get-SdnLoadBalancerMux' {
    It "Returns load balancer mux resources" {
        InModuleScope SdnDiag.NetworkController {
            Mock Invoke-RestMethodWithRetry {
                $path = ([Uri]$Uri).AbsolutePath
                if ($path -match '/networking/v1/(.+)$') {
                    $resourceType = ($Matches[1] -split '/')[0]
                    return [PSCustomObject]@{ value = $Global:PesterOfflineTests.SdnApiResources[$resourceType] }
                }
            }
            $muxes = Get-SdnLoadBalancerMux -NcUri "https://dvlab-nc.dvlab.contoso.local"
            $muxes.Count | Should -Be 2
            $muxes[0].resourceRef | Should -Not -BeNullOrEmpty
        }
    }

    It "Returns management addresses as strings with -ManagementAddressOnly" {
        InModuleScope SdnDiag.NetworkController {
            Mock Invoke-RestMethodWithRetry {
                $path = ([Uri]$Uri).AbsolutePath
                if ($path -match '/networking/v1/(.+)$') {
                    $resourceType = ($Matches[1] -split '/')[0]
                    $refKey = "/$($Matches[1])"
                    if ($Global:PesterOfflineTests.SdnApiResourcesByRef.ContainsKey($refKey)) {
                        return $Global:PesterOfflineTests.SdnApiResourcesByRef[$refKey]
                    }
                    return [PSCustomObject]@{ value = $Global:PesterOfflineTests.SdnApiResources[$resourceType] }
                }
            }
            $muxes = Get-SdnLoadBalancerMux -NcUri "https://dvlab-nc.dvlab.contoso.local" -ManagementAddressOnly
            $muxes.Count | Should -BeGreaterThan 0
            $muxes[0].GetType().Name | Should -Be "String"
        }
    }
}

Describe 'NetworkController - Get-SdnResource' {
    It "Returns servers when Resource is Servers" {
        InModuleScope SdnDiag.NetworkController {
            Mock Invoke-RestMethodWithRetry {
                $path = ([Uri]$Uri).AbsolutePath
                if ($path -match '/networking/v1/(.+)$') {
                    $resourceType = ($Matches[1] -split '/')[0]
                    return [PSCustomObject]@{ value = $Global:PesterOfflineTests.SdnApiResources[$resourceType] }
                }
            }
            $result = Get-SdnResource -NcUri "https://dvlab-nc.dvlab.contoso.local" -Resource Servers
            $result.Count | Should -BeGreaterThan 0
        }
    }

    It "Returns gateways when Resource is Gateways" {
        InModuleScope SdnDiag.NetworkController {
            Mock Invoke-RestMethodWithRetry {
                $path = ([Uri]$Uri).AbsolutePath
                if ($path -match '/networking/v1/(.+)$') {
                    $resourceType = ($Matches[1] -split '/')[0]
                    return [PSCustomObject]@{ value = $Global:PesterOfflineTests.SdnApiResources[$resourceType] }
                }
            }
            $result = Get-SdnResource -NcUri "https://dvlab-nc.dvlab.contoso.local" -Resource Gateways
            $result.Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'NetworkController - Get-SdnNetworkInterfaceOutboundPublicIPAddress' {
    It "Returns public IP for NIC with a direct instance-level publicIPAddress (tenantvm1)" {
        InModuleScope SdnDiag.NetworkController {
            Mock Invoke-RestMethodWithRetry {
                $path = ([Uri]$Uri).AbsolutePath
                if ($path -match '/networking/v1/(.+)$') {
                    $resourceType = ($Matches[1] -split '/')[0]
                    $refKey = "/$($Matches[1])"
                    if ($Global:PesterOfflineTests.SdnApiResourcesByRef.ContainsKey($refKey)) {
                        return $Global:PesterOfflineTests.SdnApiResourcesByRef[$refKey]
                    }
                    return [PSCustomObject]@{ value = $Global:PesterOfflineTests.SdnApiResources[$resourceType] }
                }
            }
            $result = Get-SdnNetworkInterfaceOutboundPublicIPAddress -NcUri "https://dvlab-nc.dvlab.contoso.local" -ResourceId "tenantvm1"
            $result | Should -Not -BeNullOrEmpty
            $result[0].PublicIPAddress | Should -Be "40.40.40.5"
            $result[0].PublicIPResourceRef | Should -Be "/publicIPAddresses/pip-tenant-0001"
        }
    }

    It "Returns public IP for NIC using LB outbound NAT with publicIPAddress on frontend (tenantvm2)" {
        InModuleScope SdnDiag.NetworkController {
            Mock Invoke-RestMethodWithRetry {
                $path = ([Uri]$Uri).AbsolutePath
                if ($path -match '/networking/v1/(.+)$') {
                    $resourceType = ($Matches[1] -split '/')[0]
                    $refKey = "/$($Matches[1])"
                    if ($Global:PesterOfflineTests.SdnApiResourcesByRef.ContainsKey($refKey)) {
                        return $Global:PesterOfflineTests.SdnApiResourcesByRef[$refKey]
                    }
                    return [PSCustomObject]@{ value = $Global:PesterOfflineTests.SdnApiResources[$resourceType] }
                }
            }
            $result = Get-SdnNetworkInterfaceOutboundPublicIPAddress -NcUri "https://dvlab-nc.dvlab.contoso.local" -ResourceId "tenantvm2"
            $result | Should -Not -BeNullOrEmpty
            $result[0].PublicIPAddress | Should -Be "40.40.40.4"
            $result[0].PublicIPResourceRef | Should -Be "/publicIPAddresses/pip-outbound-0001"
        }
    }

    It "Returns public IP for NIC using LB outbound NAT with static privateIPAddress on frontend (tenantvm3)" {
        InModuleScope SdnDiag.NetworkController {
            Mock Invoke-RestMethodWithRetry {
                $path = ([Uri]$Uri).AbsolutePath
                if ($path -match '/networking/v1/(.+)$') {
                    $resourceType = ($Matches[1] -split '/')[0]
                    $refKey = "/$($Matches[1])"
                    if ($Global:PesterOfflineTests.SdnApiResourcesByRef.ContainsKey($refKey)) {
                        return $Global:PesterOfflineTests.SdnApiResourcesByRef[$refKey]
                    }
                    return [PSCustomObject]@{ value = $Global:PesterOfflineTests.SdnApiResources[$resourceType] }
                }
            }
            $result = Get-SdnNetworkInterfaceOutboundPublicIPAddress -NcUri "https://dvlab-nc.dvlab.contoso.local" -ResourceId "tenantvm3"
            $result | Should -Not -BeNullOrEmpty
            $result[0].PublicIPAddress | Should -Be "40.40.40.6"
            $result[0].PublicIPResourceRef | Should -BeNullOrEmpty
        }
    }

    It "Returns empty result for NIC with no public IP association (nic-vm01-0001)" {
        InModuleScope SdnDiag.NetworkController {
            Mock Invoke-RestMethodWithRetry {
                $path = ([Uri]$Uri).AbsolutePath
                if ($path -match '/networking/v1/(.+)$') {
                    $resourceType = ($Matches[1] -split '/')[0]
                    $refKey = "/$($Matches[1])"
                    if ($Global:PesterOfflineTests.SdnApiResourcesByRef.ContainsKey($refKey)) {
                        return $Global:PesterOfflineTests.SdnApiResourcesByRef[$refKey]
                    }
                    return [PSCustomObject]@{ value = $Global:PesterOfflineTests.SdnApiResources[$resourceType] }
                }
            }
            $result = Get-SdnNetworkInterfaceOutboundPublicIPAddress -NcUri "https://dvlab-nc.dvlab.contoso.local" -ResourceId "nic-vm01-0001"
            $result.Count | Should -Be 0
        }
    }
}

Describe 'NetworkController - Remove-BgpLearnedRoute' {
    Context 'networkConnections resource' {
        It "Removes BGP learned routes and retains the statically configured routes" {
            InModuleScope SdnDiag.NetworkController {
                $connection = $Global:PesterOfflineTests.SdnApiResourcesByRef['/VirtualGateways/vgw-tenant-0002'].properties.networkConnections[0]
                $result = Remove-BgpLearnedRoute -Object $connection
                $result.properties.routes.Count | Should -Be 1
                $result.properties.routes[0].protocol | Should -Be 'Static'
                $result.properties.routes[0].destinationPrefix | Should -Be '172.16.10.0/24'
            }
        }

        It "Matches the protocol value without regard to casing" {
            InModuleScope SdnDiag.NetworkController {
                $connection = [PSCustomObject]@{
                    resourceRef = '/VirtualGateways/vgw-tenant-0002/networkConnections/nc-case'
                    properties  = [PSCustomObject]@{
                        routes = @(
                            [PSCustomObject]@{ destinationPrefix = '10.0.0.0/24'; protocol = 'BGP' }
                            [PSCustomObject]@{ destinationPrefix = '10.1.0.0/24'; protocol = 'bgp' }
                            [PSCustomObject]@{ destinationPrefix = '10.2.0.0/24'; protocol = 'Bgp' }
                            [PSCustomObject]@{ destinationPrefix = '10.3.0.0/24'; protocol = 'Static' }
                        )
                    }
                }
                $result = Remove-BgpLearnedRoute -Object $connection
                $result.properties.routes.Count | Should -Be 1
                $result.properties.routes[0].destinationPrefix | Should -Be '10.3.0.0/24'
            }
        }

        It "Retains routes that do not report a protocol" {
            InModuleScope SdnDiag.NetworkController {
                $connection = [PSCustomObject]@{
                    properties = [PSCustomObject]@{
                        routes = @(
                            [PSCustomObject]@{ destinationPrefix = '10.0.0.0/24' }
                            [PSCustomObject]@{ destinationPrefix = '10.1.0.0/24'; protocol = 'Bgp' }
                        )
                    }
                }
                $result = Remove-BgpLearnedRoute -Object $connection
                $result.properties.routes.Count | Should -Be 1
                $result.properties.routes[0].destinationPrefix | Should -Be '10.0.0.0/24'
            }
        }

        It "Serializes to an empty array when every route was learned via BGP" {
            InModuleScope SdnDiag.NetworkController {
                $connection = [PSCustomObject]@{
                    properties = [PSCustomObject]@{
                        routes = @([PSCustomObject]@{ destinationPrefix = '10.0.0.0/24'; protocol = 'Bgp' })
                    }
                }
                $result = Remove-BgpLearnedRoute -Object $connection
                $result.properties.routes.Count | Should -Be 0
                ($result | ConvertTo-Json -Depth 10 -Compress).Contains('"routes":[]') | Should -BeTrue
            }
        }

        It "Preserves the remaining properties of the resource" {
            InModuleScope SdnDiag.NetworkController {
                $connection = $Global:PesterOfflineTests.SdnApiResourcesByRef['/VirtualGateways/vgw-tenant-0002'].properties.networkConnections[0]
                $result = Remove-BgpLearnedRoute -Object $connection
                $result.resourceId | Should -Be 'nc-tenant-0002-ipsec'
                $result.resourceRef | Should -Be '/VirtualGateways/vgw-tenant-0002/networkConnections/nc-tenant-0002-ipsec'
                $result.etag | Should -Be $connection.etag
                $result.properties.connectionType | Should -Be 'IPSec'
                $result.properties.destinationIpAddress | Should -Be '40.40.40.10'
            }
        }

        It "Does not modify the object supplied by the caller" {
            InModuleScope SdnDiag.NetworkController {
                $connection = $Global:PesterOfflineTests.SdnApiResourcesByRef['/VirtualGateways/vgw-tenant-0002'].properties.networkConnections[0]
                $before = $connection | ConvertTo-Json -Depth 100 -Compress
                $null = Remove-BgpLearnedRoute -Object $connection
                ($connection | ConvertTo-Json -Depth 100 -Compress) | Should -Be $before
            }
        }

        It "Returns the original object when there are no BGP learned routes" {
            InModuleScope SdnDiag.NetworkController {
                $connection = [PSCustomObject]@{
                    properties = [PSCustomObject]@{
                        routes = @([PSCustomObject]@{ destinationPrefix = '10.0.0.0/24'; protocol = 'Static' })
                    }
                }
                $result = Remove-BgpLearnedRoute -Object $connection
                [System.Object]::ReferenceEquals($result, $connection) | Should -BeTrue
            }
        }

        It "Returns the original object when the resource has no routes" {
            InModuleScope SdnDiag.NetworkController {
                $server = $Global:PesterOfflineTests.SdnApiResourcesByRef['/servers/DVLAB-S1-N01']
                $result = Remove-BgpLearnedRoute -Object $server
                [System.Object]::ReferenceEquals($result, $server) | Should -BeTrue
            }
        }
    }

    Context 'virtualGateways resource' {
        It "Removes BGP learned routes from networkConnections nested under the gateway" {
            InModuleScope SdnDiag.NetworkController {
                $gateway = $Global:PesterOfflineTests.SdnApiResourcesByRef['/VirtualGateways/vgw-tenant-0002']
                $before = $gateway | ConvertTo-Json -Depth 100 -Compress
                $result = Remove-BgpLearnedRoute -Object $gateway
                $result.properties.networkConnections[0].properties.routes.Count | Should -Be 1
                $result.properties.networkConnections[0].properties.routes[0].protocol | Should -Be 'Static'
                ($gateway | ConvertTo-Json -Depth 100 -Compress) | Should -Be $before
            }
        }

        It "Returns the original object when the gateway has no network connections" {
            InModuleScope SdnDiag.NetworkController {
                $gateway = $Global:PesterOfflineTests.SdnApiResourcesByRef['/VirtualGateways/vgw-tenant-0001']
                $result = Remove-BgpLearnedRoute -Object $gateway
                [System.Object]::ReferenceEquals($result, $gateway) | Should -BeTrue
            }
        }

        It "Handles a null entry within the networkConnections array" {
            InModuleScope SdnDiag.NetworkController {
                $gateway = [PSCustomObject]@{
                    resourceRef = '/VirtualGateways/vgw-tenant-0003'
                    properties  = [PSCustomObject]@{
                        networkConnections = @(
                            $null
                            [PSCustomObject]@{
                                properties = [PSCustomObject]@{
                                    routes = @(
                                        [PSCustomObject]@{ destinationPrefix = '10.0.0.0/24'; protocol = 'Static' }
                                        [PSCustomObject]@{ destinationPrefix = '10.1.0.0/24'; protocol = 'Bgp' }
                                    )
                                }
                            }
                        )
                    }
                }
                $result = Remove-BgpLearnedRoute -Object $gateway
                $result.properties.networkConnections.Count | Should -Be 2
                $result.properties.networkConnections[0] | Should -BeNullOrEmpty
                $result.properties.networkConnections[1].properties.routes.Count | Should -Be 1
            }
        }
    }
}

Describe 'NetworkController - Set-SdnResource' {
    It "Excludes BGP learned routes from the body of a networkConnections PUT" {
        InModuleScope SdnDiag.NetworkController {
            $Global:PesterPutBody = $null
            Mock Confirm-ProvisioningStateSucceeded { return $true }
            Mock Invoke-RestMethodWithRetry {
                if ($null -ne $Body) {
                    $Global:PesterPutBody = $Body
                    return $null
                }
                return [PSCustomObject]@{ properties = [PSCustomObject]@{ provisioningState = 'Succeeded' } }
            }

            $connection = $Global:PesterOfflineTests.SdnApiResourcesByRef['/VirtualGateways/vgw-tenant-0002'].properties.networkConnections[0]
            $null = Set-SdnResource -NcUri "https://dvlab-nc.dvlab.contoso.local" -ResourceRef $connection.resourceRef -Object $connection -OperationType 'Update' -Confirm:$false

            # assert against the raw body so the routes array is proven to serialize as a JSON array
            $Global:PesterPutBody.Replace(' ', '').Replace("`r", '').Replace("`n", '') | Should -BeLike '*"routes":`[`{*'
            $body = $Global:PesterPutBody | ConvertFrom-Json
            $body.properties.routes.Count | Should -Be 1
            $body.properties.routes[0].protocol | Should -Be 'Static'
            $body.properties.routes[0].destinationPrefix | Should -Be '172.16.10.0/24'
        }
    }

    It "Sends an empty routes array when every route was learned via BGP" {
        InModuleScope SdnDiag.NetworkController {
            $Global:PesterPutBody = $null
            Mock Confirm-ProvisioningStateSucceeded { return $true }
            Mock Invoke-RestMethodWithRetry {
                if ($null -ne $Body) {
                    $Global:PesterPutBody = $Body
                    return $null
                }
                return [PSCustomObject]@{ properties = [PSCustomObject]@{ provisioningState = 'Succeeded' } }
            }

            $connection = [PSCustomObject]@{
                resourceId  = 'nc-tenant-0002-allbgp'
                resourceRef = '/VirtualGateways/vgw-tenant-0002/networkConnections/nc-tenant-0002-allbgp'
                properties  = [PSCustomObject]@{
                    routes = @([PSCustomObject]@{ destinationPrefix = '172.16.20.0/24'; protocol = 'BGP' })
                }
            }
            $null = Set-SdnResource -NcUri "https://dvlab-nc.dvlab.contoso.local" -ResourceRef $connection.resourceRef -Object $connection -OperationType 'Update' -Confirm:$false

            $Global:PesterPutBody.Replace(' ', '').Replace("`r", '').Replace("`n", '').Contains('"routes":[]') | Should -BeTrue
        }
    }

    It "Excludes BGP learned routes when the resource is targeted by name and id" {
        InModuleScope SdnDiag.NetworkController {
            $Global:PesterPutBody = $null
            Mock Confirm-ProvisioningStateSucceeded { return $true }
            Mock Invoke-RestMethodWithRetry {
                if ($null -ne $Body) {
                    $Global:PesterPutBody = $Body
                    return $null
                }
                return [PSCustomObject]@{ properties = [PSCustomObject]@{ provisioningState = 'Succeeded' } }
            }

            $gateway = $Global:PesterOfflineTests.SdnApiResourcesByRef['/VirtualGateways/vgw-tenant-0002']
            $null = Set-SdnResource -NcUri "https://dvlab-nc.dvlab.contoso.local" -Resource 'VirtualGateways' -ResourceId $gateway.resourceId -Object $gateway -OperationType 'Update' -Confirm:$false

            $body = $Global:PesterPutBody | ConvertFrom-Json
            $body.properties.networkConnections[0].properties.routes.Count | Should -Be 1
            $body.properties.networkConnections[0].properties.routes[0].protocol | Should -Be 'Static'
        }
    }

    It "Excludes BGP learned routes nested under a virtualGateways PUT" {
        InModuleScope SdnDiag.NetworkController {
            $Global:PesterPutBody = $null
            Mock Confirm-ProvisioningStateSucceeded { return $true }
            Mock Invoke-RestMethodWithRetry {
                if ($null -ne $Body) {
                    $Global:PesterPutBody = $Body
                    return $null
                }
                return [PSCustomObject]@{ properties = [PSCustomObject]@{ provisioningState = 'Succeeded' } }
            }

            $gateway = $Global:PesterOfflineTests.SdnApiResourcesByRef['/VirtualGateways/vgw-tenant-0002']
            $null = Set-SdnResource -NcUri "https://dvlab-nc.dvlab.contoso.local" -ResourceRef $gateway.resourceRef -Object $gateway -OperationType 'Update' -Confirm:$false

            $body = $Global:PesterPutBody | ConvertFrom-Json
            $body.properties.networkConnections[0].properties.routes.Count | Should -Be 1
            $body.properties.networkConnections[0].properties.routes[0].protocol | Should -Be 'Static'
        }
    }

    It "Leaves the routes array untouched for resources that are not gateway related" {
        InModuleScope SdnDiag.NetworkController {
            $Global:PesterPutBody = $null
            Mock Confirm-ProvisioningStateSucceeded { return $true }
            Mock Invoke-RestMethodWithRetry {
                if ($null -ne $Body) {
                    $Global:PesterPutBody = $Body
                    return $null
                }
                return [PSCustomObject]@{ properties = [PSCustomObject]@{ provisioningState = 'Succeeded' } }
            }

            $routeTable = [PSCustomObject]@{
                resourceId  = 'rt-tenant-0001'
                resourceRef = '/routeTables/rt-tenant-0001'
                properties  = [PSCustomObject]@{
                    routes = @(
                        [PSCustomObject]@{ destinationPrefix = '10.0.0.0/24'; protocol = 'Static' }
                        [PSCustomObject]@{ destinationPrefix = '10.1.0.0/24'; protocol = 'Bgp' }
                    )
                }
            }
            $null = Set-SdnResource -NcUri "https://dvlab-nc.dvlab.contoso.local" -ResourceRef $routeTable.resourceRef -Object $routeTable -OperationType 'Update' -Confirm:$false

            $body = $Global:PesterPutBody | ConvertFrom-Json
            $body.properties.routes.Count | Should -Be 2
        }
    }
}
