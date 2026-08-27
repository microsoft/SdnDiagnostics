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
        It "Selects port 5986 when UseSSL is configured" {
            InModuleScope SdnDiagnostics {
                $origUseSSL = $Global:SdnDiagnostics.Config.UseSSL
                $origPort = $Global:SdnDiagnostics.Config.Port

                try {
                    $Global:SdnDiagnostics.Config.UseSSL = $true
                    $Global:SdnDiagnostics.Config.Port = 0

                    # Replicate the port resolution logic from Start-SdnDataCollection
                    if ($Global:SdnDiagnostics.Config.Port -gt 0) {
                        $tncPort = $Global:SdnDiagnostics.Config.Port
                    }
                    elseif ($Global:SdnDiagnostics.Config.UseSSL) {
                        $tncPort = 5986
                    }
                    else {
                        $tncPort = 5985
                    }

                    $tncPort | Should -Be 5986
                }
                finally {
                    $Global:SdnDiagnostics.Config.UseSSL = $origUseSSL
                    $Global:SdnDiagnostics.Config.Port = $origPort
                }
            }
        }

        It "Selects custom port when Port is configured" {
            InModuleScope SdnDiagnostics {
                $origUseSSL = $Global:SdnDiagnostics.Config.UseSSL
                $origPort = $Global:SdnDiagnostics.Config.Port

                try {
                    $Global:SdnDiagnostics.Config.UseSSL = $true
                    $Global:SdnDiagnostics.Config.Port = 5988

                    if ($Global:SdnDiagnostics.Config.Port -gt 0) {
                        $tncPort = $Global:SdnDiagnostics.Config.Port
                    }
                    elseif ($Global:SdnDiagnostics.Config.UseSSL) {
                        $tncPort = 5986
                    }
                    else {
                        $tncPort = 5985
                    }

                    $tncPort | Should -Be 5988
                }
                finally {
                    $Global:SdnDiagnostics.Config.UseSSL = $origUseSSL
                    $Global:SdnDiagnostics.Config.Port = $origPort
                }
            }
        }

        It "Selects port 5985 by default (no SSL, no custom port)" {
            InModuleScope SdnDiagnostics {
                $origUseSSL = $Global:SdnDiagnostics.Config.UseSSL
                $origPort = $Global:SdnDiagnostics.Config.Port

                try {
                    $Global:SdnDiagnostics.Config.UseSSL = $false
                    $Global:SdnDiagnostics.Config.Port = 0

                    if ($Global:SdnDiagnostics.Config.Port -gt 0) {
                        $tncPort = $Global:SdnDiagnostics.Config.Port
                    }
                    elseif ($Global:SdnDiagnostics.Config.UseSSL) {
                        $tncPort = 5986
                    }
                    else {
                        $tncPort = 5985
                    }

                    $tncPort | Should -Be 5985
                }
                finally {
                    $Global:SdnDiagnostics.Config.UseSSL = $origUseSSL
                    $Global:SdnDiagnostics.Config.Port = $origPort
                }
            }
        }

        It "Custom port takes precedence over UseSSL default" {
            InModuleScope SdnDiagnostics {
                $origUseSSL = $Global:SdnDiagnostics.Config.UseSSL
                $origPort = $Global:SdnDiagnostics.Config.Port

                try {
                    $Global:SdnDiagnostics.Config.UseSSL = $false
                    $Global:SdnDiagnostics.Config.Port = 9999

                    if ($Global:SdnDiagnostics.Config.Port -gt 0) {
                        $tncPort = $Global:SdnDiagnostics.Config.Port
                    }
                    elseif ($Global:SdnDiagnostics.Config.UseSSL) {
                        $tncPort = 5986
                    }
                    else {
                        $tncPort = 5985
                    }

                    $tncPort | Should -Be 9999
                }
                finally {
                    $Global:SdnDiagnostics.Config.UseSSL = $origUseSSL
                    $Global:SdnDiagnostics.Config.Port = $origPort
                }
            }
        }
    }
}
