Describe 'NetworkController - Get-SdnServer' {
    BeforeAll {
        Mock -ModuleName SdnDiagnostics Get-SdnResource {
            if (![string]::IsNullOrEmpty($ResourceRef)) {
                return $Global:PesterOfflineTests.SdnApiResourcesByRef[$ResourceRef]
            }
            else {
                return $Global:PesterOfflineTests.SdnApiResources[$ResourceType.ToString()]
            }
        }
    }

    It "Returns server resources with resourceRef populated" {
        $servers = Get-SdnServer "https://dvlab-nc.dvlab.contoso.local"
        $servers.Count | Should -BeGreaterThan 0
        $servers[0].resourceRef | Should -Not -BeNullOrEmpty
    }

    It "Returns management addresses as strings with -ManagementAddressOnly" {
        $servers = Get-SdnServer "https://dvlab-nc.dvlab.contoso.local" -ManagementAddressOnly
        $servers.Count | Should -BeGreaterThan 0
        $servers[0].GetType() | Should -Be "String"
    }

    It "Returns all 4 servers from mock data" {
        $servers = Get-SdnServer "https://dvlab-nc.dvlab.contoso.local"
        $servers.Count | Should -Be 4
    }
}

Describe 'NetworkController - Get-SdnGateway' {
    BeforeAll {
        Mock -ModuleName SdnDiagnostics Get-SdnResource {
            if (![string]::IsNullOrEmpty($ResourceRef)) {
                return $Global:PesterOfflineTests.SdnApiResourcesByRef[$ResourceRef]
            }
            else {
                return $Global:PesterOfflineTests.SdnApiResources[$ResourceType.ToString()]
            }
        }
    }

    It "Returns gateway resources" {
        $gateways = Get-SdnGateway "https://dvlab-nc.dvlab.contoso.local"
        $gateways.Count | Should -Be 3
        $gateways[0].resourceRef | Should -Not -BeNullOrEmpty
    }

    It "Returns management addresses as strings with -ManagementAddressOnly" {
        $gateways = Get-SdnGateway "https://dvlab-nc.dvlab.contoso.local" -ManagementAddressOnly
        $gateways.Count | Should -BeGreaterThan 0
        $gateways[0].GetType() | Should -Be "String"
    }
}

Describe 'NetworkController - Get-SdnLoadBalancerMux' {
    BeforeAll {
        Mock -ModuleName SdnDiagnostics Get-SdnResource {
            if (![string]::IsNullOrEmpty($ResourceRef)) {
                return $Global:PesterOfflineTests.SdnApiResourcesByRef[$ResourceRef]
            }
            else {
                return $Global:PesterOfflineTests.SdnApiResources[$ResourceType.ToString()]
            }
        }
    }

    It "Returns load balancer mux resources" {
        $muxes = Get-SdnLoadBalancerMux "https://dvlab-nc.dvlab.contoso.local"
        $muxes.Count | Should -Be 2
        $muxes[0].resourceRef | Should -Not -BeNullOrEmpty
    }

    It "Returns management addresses as strings with -ManagementAddressOnly" {
        $muxes = Get-SdnLoadBalancerMux "https://dvlab-nc.dvlab.contoso.local" -ManagementAddressOnly
        $muxes.Count | Should -BeGreaterThan 0
        $muxes[0].GetType() | Should -Be "String"
    }
}

Describe 'NetworkController - Get-SdnResource' {
    BeforeAll {
        Mock -ModuleName SdnDiagnostics Invoke-RestMethodWithRetry {
            # Route based on URI path to return appropriate mock data
            $path = ([Uri]$Uri).AbsolutePath
            if ($path -match '/networking/v1/(.+)$') {
                $resourcePath = $Matches[1]
                # Check if it's a specific resourceRef lookup
                $refKey = "/$resourcePath"
                if ($Global:PesterOfflineTests.SdnApiResourcesByRef.ContainsKey($refKey)) {
                    return $Global:PesterOfflineTests.SdnApiResourcesByRef[$refKey]
                }
                # Otherwise return collection
                $resourceType = ($resourcePath -split '/')[0]
                if ($Global:PesterOfflineTests.SdnApiResources.ContainsKey($resourceType)) {
                    return $Global:PesterOfflineTests.SdnApiResources[$resourceType]
                }
            }
            return $null
        }
    }

    It "Returns servers when ResourceType is Servers" {
        $result = Get-SdnResource -NcUri "https://dvlab-nc.dvlab.contoso.local" -ResourceType Servers
        $result.Count | Should -BeGreaterThan 0
    }

    It "Returns gateways when ResourceType is Gateways" {
        $result = Get-SdnResource -NcUri "https://dvlab-nc.dvlab.contoso.local" -ResourceType Gateways
        $result.Count | Should -BeGreaterThan 0
    }
}
