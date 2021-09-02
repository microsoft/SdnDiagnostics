Describe 'SoftwareLoadBalancer test' { 
    BeforeAll {
        Mock -ModuleName SdnDiagnostics Get-SdnResource {
            if(![string]::IsNullOrEmpty($ResourceRef)){
                return $Global:PesterOfflineTests.SdnApiResourcesByRef[$ResourceRef]
            }
            else {
                return $Global:PesterOfflineTests.SdnApiResources[$ResourceType.ToString()]
            }
        }
    }
    It "Get-SdnNetworkInterfaceOutboundPublicIPAddress able to return Public VIP from Outbound NAT Rule" {
        $publicIpInfo = Get-SdnNetworkInterfaceOutboundPublicIPAddress -NcUri "https://sdnexpnc" -ResourceId tenantvm2
        $publicIpInfo.PublicIPAddress | Should -Be "40.40.40.4"
        $publicIpInfo.IPConfigPrivateIPAddress | Should -Be "192.168.33.5"
    }

    It "Get-SdnNetworkInterfaceOutboundPublicIPAddress able to return Public VIP on network interface" {
        $publicIpInfo = Get-SdnNetworkInterfaceOutboundPublicIPAddress -NcUri "https://sdnexpnc" -ResourceId tenantvm1
        $publicIpInfo.PublicIPAddress | Should -Be "40.40.40.5"
        $publicIpInfo.IPConfigPrivateIPAddress | Should -Be "192.168.33.4"
    }
  }