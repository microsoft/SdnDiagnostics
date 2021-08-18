# Pester tests
Describe 'Debug-SdnFabricInfrastructure test' { 
    It "Debug-SdnFabricInfrastrucure run all debug with no exception" {
        $debugResult = Debug-SdnFabricInfrastructure -NetworkController $Global:PesterGlobal.configdata.NcVM -NcRestCredential $Global:PesterGlobal.NcRestCredential
    }
  }