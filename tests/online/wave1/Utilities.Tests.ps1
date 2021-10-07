# Pester tests
Describe 'Install-SdnDiagnostics test' {
    It "Install-SdnDiagnostics installed SdnDiagnostic Module successfully" {
        $infraInfo = Get-SdnInfrastructureInfo -NetworkController $Global:PesterOnlineTests.configdata.NcVM -NcRestCredential $Global:PesterOnlineTests.NcRestCredential
        Install-SdnDiagnostics -ComputerName $infraInfo.fabricNodes

        $currentModule = Get-Module SdnDiagnostics

        $remoteModuleInfo = Invoke-Command -ComputerName $infraInfo.fabricNodes -ScriptBlock{
            return (Get-Module -ListAvailable -Name SdnDiagnostics)
        }

        foreach ($moduleInfo in $remoteModuleInfo) {
            $moduleInfo.Version | Should -Be $currentModule.Version
        }
        #$infraInfo.NCUrl | Should -not -BeNullOrEmpty
    }
  }