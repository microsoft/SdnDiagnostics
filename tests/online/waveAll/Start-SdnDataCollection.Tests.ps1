# Pester tests
Describe 'Start-SdnDataCollection test' {
    It "Start-SdnDataCollection successfully collected the logs" {
        { Start-SdnDataCollection -NetworkController $Global:PesterOnlineTests.configdata.NcVM -Role NetworkController,SoftwareLoadBalancer,Gateway,Server -OutputDirectory "$PSScriptRoot\..\..\DataCollected" -IncludeLogs -NcRestCredential $Global:PesterOnlineTests.NcRestCredential } | Should -Not -Throw
    }
  }
