# Pester tests
Describe 'Debug-SdnFabricInfrastructure test' {
    It "Debug-SdnFabricInfrastrucure run all debug with no exception" {
        { Debug-SdnFabricInfrastructure -NetworkController $Global:PesterOnlineTests.configdata.NcVM -NcRestCredential $Global:PesterOnlineTests.NcRestCredential } | Should -Not -Throw
    }
  }
