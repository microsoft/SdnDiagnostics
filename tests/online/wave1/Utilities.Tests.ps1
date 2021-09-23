# Pester tests
Describe 'Install-SdnDiagnostics test' { 
    It "Install-SdnDiagnostics installed SdnDiagnostic Module successfully" {
        $infraInfo = Get-SdnInfrastructureInfo -NetworkController $Global:PesterOnlineTests.configdata.NcVM -NcRestCredential $Global:PesterOnlineTests.NcRestCredential
        Install-SdnDiagnostics -ComputerName $infraInfo.NC
        Install-SdnDiagnostics -ComputerName $infraInfo.MUX
        Install-SdnDiagnostics -ComputerName $infraInfo.Gateway
        Install-SdnDiagnostics -ComputerName $infraInfo.Host

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