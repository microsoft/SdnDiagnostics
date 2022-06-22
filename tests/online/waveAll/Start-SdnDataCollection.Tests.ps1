# Pester tests
Describe 'Start-SdnDataCollection test' {
    It "Start-SdnNetshTrace successfully started trace on Server" {
        { Start-SdnNetshTrace -ComputerName (Get-SdnInfrastructureInfo -NetworkController $Global:PesterOnlineTests.configdata.NcVM -NcRestCredential $Global:PesterOnlineTests.NcRestCredential).Server -Role Server} | Should -Not -Throw
    }

    It "Start-SdnNetshTrace successfully started trace on Mux" {
        { Start-SdnNetshTrace -ComputerName (Get-SdnInfrastructureInfo -NetworkController $Global:PesterOnlineTests.configdata.NcVM -NcRestCredential $Global:PesterOnlineTests.NcRestCredential).SoftwareLoadBalancer -Role SoftwareLoadBalancer} | Should -Not -Throw
    }

    It "Start-SdnNetshTrace successfully started trace on Gateway" {
        { Start-SdnNetshTrace -ComputerName (Get-SdnInfrastructureInfo -NetworkController $Global:PesterOnlineTests.configdata.NcVM -NcRestCredential $Global:PesterOnlineTests.NcRestCredential).Gateway -Role Gateway} | Should -Not -Throw
    }

    Start-Sleep -Seconds 60

    It "Stop-SdnNetshTrace successfully stop trace on Server" {
        { Stop-SdnNetshTrace -ComputerName (Get-SdnInfrastructureInfo -NetworkController $Global:PesterOnlineTests.configdata.NcVM -NcRestCredential $Global:PesterOnlineTests.NcRestCredential).Server} | Should -Not -Throw
    }

    It "Stop-SdnNetshTrace successfully stop trace on SoftwareLoadBalancer" {
        { Stop-SdnNetshTrace -ComputerName (Get-SdnInfrastructureInfo -NetworkController $Global:PesterOnlineTests.configdata.NcVM -NcRestCredential $Global:PesterOnlineTests.NcRestCredential).SoftwareLoadBalancer} | Should -Not -Throw
    }

    It "Stop-SdnNetshTrace successfully stop trace on Gateway" {
        { Stop-SdnNetshTrace -ComputerName (Get-SdnInfrastructureInfo -NetworkController $Global:PesterOnlineTests.configdata.NcVM -NcRestCredential $Global:PesterOnlineTests.NcRestCredential).Gateway} | Should -Not -Throw
    }

    It "Start-SdnDataCollection successfully collected the logs" {
        { Start-SdnDataCollection -NetworkController $Global:PesterOnlineTests.configdata.NcVM -Role NetworkController,SoftwareLoadBalancer,Gateway,Server -OutputDirectory "$PSScriptRoot\..\..\DataCollected" -IncludeLogs -NcRestCredential $Global:PesterOnlineTests.NcRestCredential } | Should -Not -Throw
    }
  }
