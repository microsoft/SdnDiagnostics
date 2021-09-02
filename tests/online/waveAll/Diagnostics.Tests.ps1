# Pester tests
Describe 'Debug-SdnFabricInfrastructure test' { 
    It "Debug-SdnFabricInfrastrucure run all debug with no exception" {
        $debugResult = Debug-SdnFabricInfrastructure -NetworkController $Global:PesterGlobal.configdata.NcVM -NcRestCredential $Global:PesterGlobal.NcRestCredential
    }
  }

Describe 'Test-SdnKnownIssue test' { 
    It "Test-SdnKnownIssue run all Known Issues test with no exception" {
        $testKiResult = Test-SdnKnownIssue -NetworkController $Global:PesterGlobal.configdata.NcVM -NcRestCredential $Global:PesterGlobal.NcRestCredential
    }
}

  