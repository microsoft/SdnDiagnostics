# Pester tests
Describe 'Install-SdnDiagnostic test' { 
    It "Install-SdnDiagnostic installed SdnDiagnostic Module successfully" {
        $infraInfo = Get-SdnInfrastructureInfo -NetworkController $Global:PesterOnlineTests.configdata.NcVM -NcRestCredential $Global:PesterOnlineTests.NcRestCredential
        Install-SdnDiagnostic -ComputerName $infraInfo.NC
        Install-SdnDiagnostic -ComputerName $infraInfo.MUX
        Install-SdnDiagnostic -ComputerName $infraInfo.Gateway
        Install-SdnDiagnostic -ComputerName $infraInfo.Host

        $currentModule = Get-Module SdnDiagnostics

        $allInfraMachines = [System.Collections.ArrayList]::new()
        [void]$allInfraMachines.AddRange(($infraInfo.NC))
        [void]$allInfraMachines.AddRange(($infraInfo.MUX))
        [void]$allInfraMachines.AddRange(($infraInfo.Gateway))
        [void]$allInfraMachines.AddRange(($infraInfo.Host))
        $remoteModuleInfo = Invoke-Command -ComputerName $allInfraMachines -ScriptBlock{
            return (Get-Module -ListAvailable -Name SdnDiagnostics)
        }

        foreach ($moduleInfo in $remoteModuleInfo) {
            $moduleInfo.Version | Should -Be $currentModule.Version
        }
        #$infraInfo.NCUrl | Should -not -BeNullOrEmpty
    }
  }