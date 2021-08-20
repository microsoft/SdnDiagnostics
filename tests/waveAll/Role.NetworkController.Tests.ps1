# Pester tests
Describe 'Get-SdnInfrastructureInfo test' { 
  It "Able to retreive NCUrl" {
      $infraInfo = Get-SdnInfrastructureInfo -NetworkController $Global:PesterGlobal.configdata.NcVM -NcRestCredential $Global:PesterGlobal.NcRestCredential
      $infraInfo.NCUrl | Should -not -BeNullOrEmpty
  }
  It "All NC retrieved" {
    $infraInfo = Get-SdnInfrastructureInfo -NetworkController $Global:PesterGlobal.configdata.NcVM -NcRestCredential $Global:PesterGlobal.NcRestCredential
    $infraInfo.NC.Count | Should -Be $Global:PesterGlobal.ConfigData.NumberOfNc
  }
  It "All MUX retrieved" {
    $infraInfo = Get-SdnInfrastructureInfo -NetworkController $Global:PesterGlobal.configdata.NcVM -NcRestCredential $Global:PesterGlobal.NcRestCredential
    $infraInfo.Mux.Count | Should -Be $Global:PesterGlobal.ConfigData.NumberOfMux
  }
  It "All Gateway retrieved" {
    $infraInfo = Get-SdnInfrastructureInfo -NetworkController $Global:PesterGlobal.configdata.NcVM -NcRestCredential $Global:PesterGlobal.NcRestCredential
    $infraInfo.Gateway.Count | Should -Be $Global:PesterGlobal.ConfigData.NumberOfGateway
  }

  It "All Server retrieved" {
    $infraInfo = Get-SdnInfrastructureInfo -NetworkController $Global:PesterGlobal.configdata.NcVM -NcRestCredential $Global:PesterGlobal.NcRestCredential
    $infraInfo.Host.Count | Should -Be $Global:PesterGlobal.ConfigData.NumberOfServer
  }
}

Describe 'Get-SdnNetworkController test' {
    It "Able to retrieve Network Controller details"{
        $NcInfo = Get-SdnNetworkController -NetworkController $Global:PesterGlobal.configdata.NcVM 
        $NcInfo.Count | Should -Be 3
    }
}
