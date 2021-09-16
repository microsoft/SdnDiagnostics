# Pester tests
Describe 'Debug-SdnFabricInfrastructure test' { 
    It "Debug-SdnFabricInfrastrucure run all debug with no exception" {
        $debugResult = Debug-SdnFabricInfrastructure -NetworkController $Global:PesterOnlineTests.configdata.NcVM -NcRestCredential $Global:PesterOnlineTests.NcRestCredential
    }
  }

Describe 'Test-SdnKnownIssue test' { 
    It "Test-SdnKnownIssue run all Known Issues test with no exception" {
        $testKiResult = Test-SdnKnownIssue -NetworkController $Global:PesterOnlineTests.configdata.NcVM -NcRestCredential $Global:PesterOnlineTests.NcRestCredential
    }
}

  