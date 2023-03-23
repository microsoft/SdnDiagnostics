# Pester tests
Describe 'Debug-SdnFabricInfrastructure test' {
    It "Debug-SdnFabricInfrastrucure run all debug with no exception" {
        $result = Debug-SdnFabricInfrastructure -NetworkController $Global:PesterOnlineTests.configdata.NcVM -NcRestCredential $Global:PesterOnlineTests.NcRestCredential 
        $result | Should -not -BeNullOrEmpty
    }
  }
