Describe 'NetworkController test' {
    BeforeAll {
        Mock -ModuleName SdnDiagnostics Get-SdnResource {
            return $Global:PesterOfflineTests.SdnApiResources[$ResourceType.ToString()]
        }
    }
    It "Get-SdnServer -ManagementAddress should return Server Address Only" {
        $servers = Get-SdnServer "https://sdnexpnc" -ManagementAddress
        $servers.Count | Should -BeGreaterThan 0
        $servers[0].GetType() | Should -Be "String"
    }

    It "Get-SdnServer should return Server resource" {
        $servers = Get-SdnServer "https://sdnexpnc"
        $servers.Count | Should -BeGreaterThan 0
        $servers[0].resourceRef | Should -Not -BeNullOrEmpty
    }
  }
