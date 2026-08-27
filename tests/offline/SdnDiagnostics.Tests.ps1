Describe 'Start-SdnDataCollection - UseSSL and Port configuration' -Tag 'Unit' {
    Context 'UseSSL and Port update global config' {
        It "Sets Config.UseSSL to true when -UseSSL is specified" {
            InModuleScope SdnDiagnostics {
                $origUseSSL = $Global:SdnDiagnostics.Config.UseSSL
                $origPort = $Global:SdnDiagnostics.Config.Port

                Mock Test-ComputerNameIsLocal { return $false }
                Mock Start-Transcript { return $null }
                Mock Trace-Output {}
                Mock Initialize-DataCollection { return $false }
                Mock Get-FormattedDateTimeUTC { return '20260101T000000Z' }
                Mock Get-WorkingDirectory { return '/tmp/SdnDiagTests' }
                Mock Stop-Transcript {}

                try {
                    $Global:SdnDiagnostics.Config.UseSSL = $false
                    Start-SdnDataCollection -NetworkController 'DVLAB-NC01' `
                        -ComputerName 'DVLAB-S1-N01' `
                        -UseSSL `
                        -OutputDirectory '/tmp/SdnDiagTests'

                    $Global:SdnDiagnostics.Config.UseSSL | Should -Be $true
                }
                finally {
                    $Global:SdnDiagnostics.Config.UseSSL = $origUseSSL
                    $Global:SdnDiagnostics.Config.Port = $origPort
                }
            }
        }

        It "Sets Config.Port when -Port is specified" {
            InModuleScope SdnDiagnostics {
                $origUseSSL = $Global:SdnDiagnostics.Config.UseSSL
                $origPort = $Global:SdnDiagnostics.Config.Port

                Mock Test-ComputerNameIsLocal { return $false }
                Mock Start-Transcript { return $null }
                Mock Trace-Output {}
                Mock Initialize-DataCollection { return $false }
                Mock Get-FormattedDateTimeUTC { return '20260101T000000Z' }
                Mock Get-WorkingDirectory { return '/tmp/SdnDiagTests' }
                Mock Stop-Transcript {}

                try {
                    $Global:SdnDiagnostics.Config.Port = 0
                    Start-SdnDataCollection -NetworkController 'DVLAB-NC01' `
                        -ComputerName 'DVLAB-S1-N01' `
                        -Port 5988 `
                        -OutputDirectory '/tmp/SdnDiagTests'

                    $Global:SdnDiagnostics.Config.Port | Should -Be 5988
                }
                finally {
                    $Global:SdnDiagnostics.Config.UseSSL = $origUseSSL
                    $Global:SdnDiagnostics.Config.Port = $origPort
                }
            }
        }

        It "Does not modify Config.UseSSL when not specified" {
            InModuleScope SdnDiagnostics {
                $origUseSSL = $Global:SdnDiagnostics.Config.UseSSL
                $origPort = $Global:SdnDiagnostics.Config.Port

                Mock Test-ComputerNameIsLocal { return $false }
                Mock Start-Transcript { return $null }
                Mock Trace-Output {}
                Mock Initialize-DataCollection { return $false }
                Mock Get-FormattedDateTimeUTC { return '20260101T000000Z' }
                Mock Get-WorkingDirectory { return '/tmp/SdnDiagTests' }
                Mock Stop-Transcript {}

                try {
                    $Global:SdnDiagnostics.Config.UseSSL = $false
                    Start-SdnDataCollection -NetworkController 'DVLAB-NC01' `
                        -ComputerName 'DVLAB-S1-N01' `
                        -OutputDirectory '/tmp/SdnDiagTests'

                    $Global:SdnDiagnostics.Config.UseSSL | Should -Be $false
                }
                finally {
                    $Global:SdnDiagnostics.Config.UseSSL = $origUseSSL
                    $Global:SdnDiagnostics.Config.Port = $origPort
                }
            }
        }
    }

    Context 'Preflight port selection resolves correct WinRM port' {
        InModuleScope SdnDiagnostics {
            BeforeEach {
                $script:origUseSSL = $Global:SdnDiagnostics.Config.UseSSL
                $script:origPort = $Global:SdnDiagnostics.Config.Port

                Mock Test-ComputerNameIsLocal { return $false }
                Mock Start-Transcript { return $null }
                Mock Trace-Output {}
                Mock Initialize-DataCollection { return $true }
                Mock Get-FormattedDateTimeUTC { return '20260101T000000Z' }
                Mock Get-WorkingDirectory { return '/tmp/SdnDiagTests' }
                Mock Stop-Transcript {}
                Mock Export-ObjectToFile {}
                Mock Get-SdnInfrastructureInfo {
                    return @{
                        Server = @('DVLAB-S1-N01')
                    }
                }
                Mock Get-SdnRole { return 'Server' }
                Mock Get-ComputerNameFQDNandNetBIOS {
                    return [PSCustomObject]@{ ComputerNameNetBIOS = 'DVLAB-S1-N01' }
                }
                # Mock Test-NetConnection to return $true so preflight passes;
                # the test asserts it was called with the correct Port argument.
                Mock Test-NetConnection { return $true }
                # Stop execution after preflight by failing Install-SdnDiagnostics
                Mock Install-SdnDiagnostics { throw 'stop-after-preflight' }
            }
            AfterEach {
                $Global:SdnDiagnostics.Config.UseSSL = $script:origUseSSL
                $Global:SdnDiagnostics.Config.Port = $script:origPort
            }

            It "Probes port 5986 when -UseSSL is specified" {
                $Global:SdnDiagnostics.Config.UseSSL = $false
                $Global:SdnDiagnostics.Config.Port = 0

                Start-SdnDataCollection -NetworkController 'DVLAB-NC01' `
                    -ComputerName 'DVLAB-S1-N01' `
                    -UseSSL `
                    -OutputDirectory '/tmp/SdnDiagTests' -ErrorAction SilentlyContinue

                Should -Invoke Test-NetConnection -ParameterFilter { $Port -eq 5986 }
            }

            It "Probes custom port when -Port is specified" {
                $Global:SdnDiagnostics.Config.UseSSL = $false
                $Global:SdnDiagnostics.Config.Port = 0

                Start-SdnDataCollection -NetworkController 'DVLAB-NC01' `
                    -ComputerName 'DVLAB-S1-N01' `
                    -Port 5988 `
                    -OutputDirectory '/tmp/SdnDiagTests' -ErrorAction SilentlyContinue

                Should -Invoke Test-NetConnection -ParameterFilter { $Port -eq 5988 }
            }

            It "Probes port 5985 by default (no SSL, no custom port)" {
                $Global:SdnDiagnostics.Config.UseSSL = $false
                $Global:SdnDiagnostics.Config.Port = 0

                Start-SdnDataCollection -NetworkController 'DVLAB-NC01' `
                    -ComputerName 'DVLAB-S1-N01' `
                    -OutputDirectory '/tmp/SdnDiagTests' -ErrorAction SilentlyContinue

                Should -Invoke Test-NetConnection -ParameterFilter { $Port -eq 5985 }
            }

            It "Custom port takes precedence over UseSSL default" {
                $Global:SdnDiagnostics.Config.UseSSL = $false
                $Global:SdnDiagnostics.Config.Port = 0

                Start-SdnDataCollection -NetworkController 'DVLAB-NC01' `
                    -ComputerName 'DVLAB-S1-N01' `
                    -UseSSL -Port 9999 `
                    -OutputDirectory '/tmp/SdnDiagTests' -ErrorAction SilentlyContinue

                Should -Invoke Test-NetConnection -ParameterFilter { $Port -eq 9999 }
            }
        }
    }
}
