Describe 'LoadBalancerMux test' {
    It "Get-SdnNetworkInterfaceOutboundPublicIPAddress able to return Public VIP from Outbound NAT Rule" {
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
            $publicIpInfo = Get-SdnNetworkInterfaceOutboundPublicIPAddress -NcUri "https://dvlab-nc.dvlab.contoso.local" -ResourceId tenantvm2
            $publicIpInfo.PublicIPAddress | Should -Be "40.40.40.4"
            $publicIpInfo.IPConfigPrivateIPAddress | Should -Be "192.168.33.5"
        }
    }

    It "Get-SdnNetworkInterfaceOutboundPublicIPAddress able to return Public VIP on network interface" {
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
            $publicIpInfo = Get-SdnNetworkInterfaceOutboundPublicIPAddress -NcUri "https://dvlab-nc.dvlab.contoso.local" -ResourceId tenantvm1
            $publicIpInfo.PublicIPAddress | Should -Be "40.40.40.5"
            $publicIpInfo.IPConfigPrivateIPAddress | Should -Be "192.168.33.4"
        }
    }
}
