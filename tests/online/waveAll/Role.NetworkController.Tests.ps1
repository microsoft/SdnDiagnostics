# Pester tests
Describe 'Get-SdnInfrastructureInfo test' { 
  It "Able to retreive NCUrl" {
      $infraInfo = Get-SdnInfrastructureInfo -NetworkController $Global:PesterOnlineTests.configdata.NcVM -NcRestCredential $Global:PesterOnlineTests.NcRestCredential
      $infraInfo.NCUrl | Should -not -BeNullOrEmpty
  }
  It "All NC retrieved" {
    $infraInfo = Get-SdnInfrastructureInfo -NetworkController $Global:PesterOnlineTests.configdata.NcVM -NcRestCredential $Global:PesterOnlineTests.NcRestCredential
    $infraInfo.NC.Count | Should -Be $Global:PesterOnlineTests.ConfigData.NumberOfNc
  }
  It "All MUX retrieved" {
    $infraInfo = Get-SdnInfrastructureInfo -NetworkController $Global:PesterOnlineTests.configdata.NcVM -NcRestCredential $Global:PesterOnlineTests.NcRestCredential
    $infraInfo.Mux.Count | Should -Be $Global:PesterOnlineTests.ConfigData.NumberOfMux
  }
  It "All Gateway retrieved" {
    $infraInfo = Get-SdnInfrastructureInfo -NetworkController $Global:PesterOnlineTests.configdata.NcVM -NcRestCredential $Global:PesterOnlineTests.NcRestCredential
    $infraInfo.Gateway.Count | Should -Be $Global:PesterOnlineTests.ConfigData.NumberOfGateway
  }

  It "All Server retrieved" {
    $infraInfo = Get-SdnInfrastructureInfo -NetworkController $Global:PesterOnlineTests.configdata.NcVM -NcRestCredential $Global:PesterOnlineTests.NcRestCredential
    $infraInfo.Host.Count | Should -Be $Global:PesterOnlineTests.ConfigData.NumberOfServer
  }
}

Describe 'Get-SdnNetworkController test' {
    It "Able to retrieve Network Controller details"{
        $NcInfo = Get-SdnNetworkController -NetworkController $Global:PesterOnlineTests.configdata.NcVM
        $NcInfo.Count | Should -Be 3
    }
}
