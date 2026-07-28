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
