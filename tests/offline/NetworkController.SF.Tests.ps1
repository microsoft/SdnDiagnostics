Describe 'NetworkController.SF - Invoke-SdnServiceFabricCommand' -Tag 'Unit' {
    Context 'Remote transport settings' {
        It "Uses port 5985 without SSL by default (HTTP)" {
            InModuleScope SdnDiag.NetworkController.SF {
                Mock Test-ComputerNameIsLocal { return $false }
                Mock Invoke-Command { return 'mocked-response' }

                $originalClusterConfigType = $Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType
                $Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType = 'ServiceFabric'
                $Global:SdnDiagnostics.Config.UseSSL = $false
                $Global:SdnDiagnostics.Config.Port = 0
                try {
                    Invoke-SdnServiceFabricCommand -NetworkController 'DVLAB-NC01' -ScriptBlock { Get-ServiceFabricClusterHealth }

                    Should -Invoke Invoke-Command -Times 1 -ParameterFilter {
                        $ComputerName -eq 'DVLAB-NC01' -and $Port -eq 5985 -and (-not $UseSSL)
                    }
                }
                finally {
                    $Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType = $originalClusterConfigType
                    $Global:SdnDiagnostics.Config.UseSSL = $false
                    $Global:SdnDiagnostics.Config.Port = 0
                }
            }
        }

        It "Uses port 5986 with SSL when global config UseSSL is enabled" {
            InModuleScope SdnDiag.NetworkController.SF {
                Mock Test-ComputerNameIsLocal { return $false }
                Mock Invoke-Command { return 'mocked-response' }

                $originalClusterConfigType = $Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType
                $Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType = 'ServiceFabric'
                $Global:SdnDiagnostics.Config.UseSSL = $true
                $Global:SdnDiagnostics.Config.Port = 0
                try {
                    Invoke-SdnServiceFabricCommand -NetworkController 'DVLAB-NC01' -ScriptBlock { Get-ServiceFabricClusterHealth }

                    Should -Invoke Invoke-Command -Times 1 -ParameterFilter {
                        $Port -eq 5986 -and $UseSSL -eq $true
                    }
                }
                finally {
                    $Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType = $originalClusterConfigType
                    $Global:SdnDiagnostics.Config.UseSSL = $false
                    $Global:SdnDiagnostics.Config.Port = 0
                }
            }
        }

        It "Uses the custom port defined within the global config" {
            InModuleScope SdnDiag.NetworkController.SF {
                Mock Test-ComputerNameIsLocal { return $false }
                Mock Invoke-Command { return 'mocked-response' }

                $originalClusterConfigType = $Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType
                $Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType = 'ServiceFabric'
                $Global:SdnDiagnostics.Config.UseSSL = $true
                $Global:SdnDiagnostics.Config.Port = 5987
                try {
                    Invoke-SdnServiceFabricCommand -NetworkController 'DVLAB-NC01' -ScriptBlock { Get-ServiceFabricClusterHealth }

                    Should -Invoke Invoke-Command -Times 1 -ParameterFilter {
                        $Port -eq 5987 -and $UseSSL -eq $true
                    }
                }
                finally {
                    $Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType = $originalClusterConfigType
                    $Global:SdnDiagnostics.Config.UseSSL = $false
                    $Global:SdnDiagnostics.Config.Port = 0
                }
            }
        }

        It "Does not add transport settings when executed against the local computer" {
            InModuleScope SdnDiag.NetworkController.SF {
                Mock Test-ComputerNameIsLocal { return $true }
                Mock Confirm-IsNetworkController {}
                Mock Invoke-Command { return 'mocked-response' }

                $originalClusterConfigType = $Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType
                $Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType = 'ServiceFabric'
                $Global:SdnDiagnostics.Config.UseSSL = $true
                $Global:SdnDiagnostics.Config.Port = 5987
                try {
                    Invoke-SdnServiceFabricCommand -NetworkController 'DVLAB-NC01' -ScriptBlock { Get-ServiceFabricClusterHealth }

                    Should -Invoke Invoke-Command -Times 1 -ParameterFilter {
                        (-not $ComputerName) -and (-not $Port) -and (-not $UseSSL)
                    }
                }
                finally {
                    $Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType = $originalClusterConfigType
                    $Global:SdnDiagnostics.Config.UseSSL = $false
                    $Global:SdnDiagnostics.Config.Port = 0
                }
            }
        }
    }
}
