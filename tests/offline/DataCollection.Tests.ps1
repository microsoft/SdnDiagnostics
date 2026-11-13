Describe 'SdnDiagnostics - optional structured diagnostics' {
    InModuleScope SdnDiagnostics {
        BeforeEach {
            Mock Trace-Output -RemoveParameterType Level {}
            Mock Trace-Exception {}
            Mock Start-Transcript {}
            Mock Stop-Transcript {}
            Mock Get-WorkingDirectory { $TestDrive }
            Mock Get-FormattedDateTimeUTC { [guid]::NewGuid().ToString('N') }
            Mock Initialize-DataCollection {
                $null = New-Item -Path $FilePath -ItemType Directory -Force
                $true
            }
            Mock Get-ComputerNameFQDNandNetBIOS {
                [PSCustomObject]@{ ComputerNameNetBIOS = ($ComputerName -split '\.')[0]; ComputerNameFQDN = $ComputerName }
            }
            Mock Get-SdnRole { 'Server' }
            Mock Test-ComputerNameIsLocal { $false }
            Mock Test-NetConnection { $true }
            if ($PSVersionTable.PSVersion.Major -ge 7) {
                # Do not execute the legacy parallel connectivity check outside the mock scope.
                Mock ForEach-Object -ParameterFilter { $Parallel } {}
            }
            Mock Install-SdnDiagnostics {}
            Mock Confirm-IsNetworkController {}
            Mock Get-SdnInfrastructureInfo {
                @{
                    NcUrl = 'https://dvlab-nc.dvlab.contoso.local'
                    Server = @('DVLAB-S1-N01', 'DVLAB-S1-N02')
                    NetworkController = @('DVLAB-S1-N01')
                }
            }
            Mock Get-SdnSlbStateInformation { @{ State = 'DVLAB' } }
            Mock Invoke-SdnResourceDump {}
            Mock Get-SdnNetworkControllerState {}
            Mock Get-SdnNetworkControllerClusterInfo {}
            Mock Get-SdnFabricInfrastructureResult {}
            Mock Get-SdnAuditLogSetting { @{ Enabled = $false } }
            Mock Get-FolderSize { 123 }
            Mock Export-ObjectToFile {}
            Mock Remove-SdnDiagnosticJob {}
            Mock Clear-SdnWorkingDirectory {}
            Mock Get-StructuredDiagnosticTarget {
                if ($ComputerName.Count -gt 0) {
                    return ($ComputerName | Select-Object -Unique)
                }
                return @('DVLAB-S1-N01', 'DVLAB-S1-N02')
            }
            Mock Invoke-PSRemoteCommand {}
            Mock Copy-FileFromRemoteComputer {}
            Mock Invoke-StructuredDiagnostics { [PSCustomObject]@{ Status = 'Completed' } }
            $script:savedClusterConfigType = $Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType
            $script:savedRoles = $Global:SdnDiagnostics.Config.Role
            $Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType = 'FailoverCluster'
            $Global:SdnDiagnostics.Config.Role = @('Common')
        }
        AfterEach {
            $Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType = $script:savedClusterConfigType
            $Global:SdnDiagnostics.Config.Role = $script:savedRoles
        }

        It 'Leaves structured collection disabled when the flag is absent' {
            $result = Start-SdnDataCollection -Role Server -NetworkController DVLAB-NC01 -OutputDirectory $TestDrive
            $result.Result | Should -Be Success
            $result.Role | Should -Be Server
            $result.ComputerName.Count | Should -Be 2
            Should -Invoke Get-SdnInfrastructureInfo -Times 1
            Should -Invoke Invoke-PSRemoteCommand -Times 2
            Should -Invoke Copy-FileFromRemoteComputer -Times 2
            Should -Invoke Clear-SdnWorkingDirectory -Times 2
            Should -Invoke Invoke-StructuredDiagnostics -Times 0
        }

        It 'Invokes the independent stage with selected hosts, credentials and dates' {
            $from = [datetime]'2026-01-01T00:00:00Z'
            $credential = [pscredential]::new('DVLAB\operator', [securestring]::new())
            $result = Start-SdnDataCollection -Role Server -NetworkController DVLAB-NC01 -OutputDirectory $TestDrive `
                -IncludeStructuredDiagnostics -IncludeLogs -FromDate $from -ToDate $from.AddHours(2) -Credential $credential
            $result.Result | Should -Be Success
            Should -Invoke Invoke-StructuredDiagnostics -Times 1 -ParameterFilter {
                $ComputerName.Count -eq 2 -and $ComputerName -contains 'DVLAB-S1-N01' -and $ComputerName -contains 'DVLAB-S1-N02' -and
                $Credential.UserName -eq 'DVLAB\operator' -and $IncludeLogs -and $OutputDirectory -like '*\SdnDataCollection_*' -and
                $FromDate -eq [datetime]'2026-01-01T00:00:00Z' -and $ToDate -eq [datetime]'2026-01-01T02:00:00Z'
            }
            Should -Invoke Get-SdnInfrastructureInfo -Times 1
            Should -Invoke Copy-FileFromRemoteComputer -Times 2
        }

        It 'Uses the existing role limit and does not enable optional logs implicitly' {
            $result = Start-SdnDataCollection -Role Server -NetworkController DVLAB-NC01 -Limit 1 -OutputDirectory $TestDrive -IncludeStructuredDiagnostics
            $result.Result | Should -Be Success
            Should -Invoke Invoke-StructuredDiagnostics -Times 1 -ParameterFilter {
                $ComputerName.Count -eq 1 -and -not $IncludeLogs
            }
        }

        It 'Deduplicates multi-role hosts only for the structured stage' {
            $result = Start-SdnDataCollection -Role Server,NetworkController -NetworkController DVLAB-NC01 -OutputDirectory $TestDrive -IncludeStructuredDiagnostics
            $result.Result | Should -Be Success
            Should -Invoke Invoke-StructuredDiagnostics -Times 1 -ParameterFilter {
                $ComputerName.Count -eq 2
            }
        }

        It 'Forwards explicit computer targets without changing discovery' {
            $result = Start-SdnDataCollection -ComputerName DVLAB-S1-N02 -NetworkController DVLAB-NC01 -OutputDirectory $TestDrive -IncludeStructuredDiagnostics
            $result.Result | Should -Be Success
            Should -Invoke Invoke-StructuredDiagnostics -Times 1 -ParameterFilter {
                $ComputerName.Count -eq 1 -and $ComputerName[0] -eq 'DVLAB-S1-N02'
            }
            Should -Invoke Get-SdnInfrastructureInfo -Times 1
        }

        It 'Surfaces structured failures through the existing collection error path' {
            Mock Invoke-StructuredDiagnostics { throw 'DVLAB structured collection failed' }
            $result = Start-SdnDataCollection -Role Server -NetworkController DVLAB-NC01 -OutputDirectory $TestDrive -IncludeStructuredDiagnostics -ErrorAction SilentlyContinue
            $result.Result | Should -Be Failed
            Should -Invoke Copy-FileFromRemoteComputer -Times 2
            Should -Invoke Trace-Exception -Times 1
        }

        It 'Returns partial structured results without failing normal SDN collection' {
            Mock Invoke-StructuredDiagnostics { [PSCustomObject]@{ Status = 'CompletedWithFailures' } }
            $result = Start-SdnDataCollection -Role Server -NetworkController DVLAB-NC01 -OutputDirectory $TestDrive -IncludeStructuredDiagnostics -ErrorAction SilentlyContinue
            $result.Result | Should -Be Success
            $result.StructuredDiagnostics.Status | Should -Be CompletedWithFailures
            Should -Invoke Copy-FileFromRemoteComputer -Times 2
            Should -Invoke Invoke-StructuredDiagnostics -Times 1
        }

        It 'Retains the NC precondition even when the flag is present' {
            Mock Test-ComputerNameIsLocal { $true }
            Mock Confirm-IsNetworkController { throw 'DVLAB NC required' }
            { Start-SdnDataCollection -Role Server -NetworkController $env:COMPUTERNAME -OutputDirectory $TestDrive -IncludeStructuredDiagnostics } | Should -Throw '*NC required*'
            Should -Invoke Invoke-StructuredDiagnostics -Times 0
        }

        It 'Uses every supplied non-SDN host without NC discovery or legacy collection' {
            $result = Start-SdnDataCollection -ComputerName DVLAB-S1-N01,DVLAB-S1-N02 -OutputDirectory $TestDrive -IncludeStructuredDiagnostics
            $result.Status | Should -Be Completed
            Should -Invoke Invoke-StructuredDiagnostics -Times 1 -ParameterFilter {
                $ComputerName.Count -eq 2 -and $ComputerName -contains 'DVLAB-S1-N01' -and $ComputerName -contains 'DVLAB-S1-N02'
            }
            Should -Invoke Get-SdnInfrastructureInfo -Times 0
            Should -Invoke Confirm-IsNetworkController -Times 0
            Should -Invoke Invoke-PSRemoteCommand -Times 0
            Should -Invoke Copy-FileFromRemoteComputer -Times 0
            Should -Invoke Clear-SdnWorkingDirectory -Times 0
        }

        It 'Retains SDN collection when the local NC role is detected' {
            $Global:SdnDiagnostics.Config.Role = @('Common', 'NetworkController')
            $result = Start-SdnDataCollection -Role Server -OutputDirectory $TestDrive -IncludeStructuredDiagnostics
            $result.Result | Should -Be Success
            Should -Invoke Get-SdnInfrastructureInfo -Times 1
            Should -Invoke Invoke-StructuredDiagnostics -Times 1
            Should -Invoke Get-StructuredDiagnosticTarget -Times 0
        }

        It 'Retains SDN collection when only NcUri supplies the NC context' {
            $result = Start-SdnDataCollection -Role Server -NcUri 'https://dvlab-nc.dvlab.contoso.local' -OutputDirectory $TestDrive -IncludeStructuredDiagnostics
            $result.Result | Should -Be Success
            Should -Invoke Get-SdnInfrastructureInfo -Times 1
            Should -Invoke Invoke-StructuredDiagnostics -Times 1
            Should -Invoke Get-StructuredDiagnosticTarget -Times 0
        }

        It 'Filters non-host SDN roles out of the structured stage' {
            Mock Get-SdnInfrastructureInfo {
                @{
                    NcUrl = 'https://dvlab-nc.dvlab.contoso.local'
                    Server = @('DVLAB-S1-N01.dvlab.contoso.local', 'DVLAB-S1-N02.dvlab.contoso.local')
                    NetworkController = @('DVLAB-NC01')
                    Gateway = @('DVLAB-GW01')
                    LoadBalancerMux = @('DVLAB-MUX01')
                }
            }
            $result = Start-SdnDataCollection -Role Server,NetworkController,Gateway,LoadBalancerMux `
                -NetworkController DVLAB-NC01 -OutputDirectory $TestDrive -IncludeStructuredDiagnostics
            $result.Result | Should -Be Success
            Should -Invoke Invoke-StructuredDiagnostics -Times 1 -ParameterFilter {
                $ComputerName.Count -eq 2 -and $ComputerName -contains 'DVLAB-S1-N01' -and
                $ComputerName -contains 'DVLAB-S1-N02'
            }
            Should -Invoke Copy-FileFromRemoteComputer -Times 5
        }

        It 'Skips the structured stage when the selected nodes are not Server hosts' {
            Mock Get-SdnInfrastructureInfo {
                @{ NcUrl = 'https://dvlab-nc.dvlab.contoso.local'; NetworkController = @('DVLAB-NC01'); Server = @() }
            }
            $result = Start-SdnDataCollection -Role NetworkController -NetworkController DVLAB-NC01 `
                -OutputDirectory $TestDrive -IncludeStructuredDiagnostics
            $result.Result | Should -Be Success
            $result.StructuredDiagnostics | Should -BeNullOrEmpty
            Should -Invoke Invoke-StructuredDiagnostics -Times 0
        }

        It 'Restores the caller progress preference after SDN connectivity validation' {
            $originalProgressPreference = $Global:ProgressPreference
            try {
                $Global:ProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
                $result = Start-SdnDataCollection -Role Server -NetworkController DVLAB-NC01 -OutputDirectory $TestDrive

                $result.Result | Should -Be Success
                $Global:ProgressPreference |
                    Should -Be ([System.Management.Automation.ActionPreference]::SilentlyContinue)
            }
            finally {
                $Global:ProgressPreference = $originalProgressPreference
            }
        }

    }
}

Describe 'SdnDiagnostics - independent structured collection integration' {
    InModuleScope SdnDiagnostics {
        It 'Reaches the internal collector without NC discovery and writes separate output' {
            $savedRoles = $Global:SdnDiagnostics.Config.Role
            $Global:SdnDiagnostics.Config.Role = @('Common')
            Mock Trace-Output -RemoveParameterType Level {}
            Mock Get-SdnInfrastructureInfo { throw 'Must not discover SDN' }
            Mock Get-StructuredDiagnosticTarget { $ComputerName }
            Mock Trace-Output -ModuleName SdnDiag.StructuredDiagnostics -RemoveParameterType Level {}
            Mock Trace-Exception -ModuleName SdnDiag.StructuredDiagnostics {}
            Mock Confirm-IsServer -ModuleName SdnDiag.StructuredDiagnostics {}
            Mock Initialize-DataCollection -ModuleName SdnDiag.StructuredDiagnostics -RemoveParameterType Role {
                $null = New-Item -Path $FilePath -ItemType Directory -Force
                $true
            }
            Mock Test-ComputerNameIsLocal -ModuleName SdnDiag.StructuredDiagnostics { $true }
            Mock Invoke-PSRemoteCommand -ModuleName SdnDiag.StructuredDiagnostics { throw 'Must not contact remote hosts' }
            $script:structuredModuleUnderTest = Get-Module SdnDiag.StructuredDiagnostics -All | Select-Object -First 1
            Mock Import-Module -ModuleName SdnDiag.StructuredDiagnostics -ParameterFilter {
                $Name -like '*\modules\SdnDiag.StructuredDiagnostics.psm1'
            } { $script:structuredModuleUnderTest }
            Mock Start-Job -ModuleName SdnDiag.StructuredDiagnostics {
                $script:localScriptBlock = $ScriptBlock
                $script:localArgumentList = $ArgumentList
                [PSCustomObject]@{ Name = 'SdnDiag-Local-DVLAB' }
            }
            Mock Wait-PSJob -ModuleName SdnDiag.StructuredDiagnostics {
                & $script:localScriptBlock @script:localArgumentList
            }
            Mock Invoke-StructuredDiagnosticCollection -ModuleName SdnDiag.StructuredDiagnostics {
                $null = New-Item -Path $OutputRoot -ItemType Directory -Force
                '{"Status":"Completed"}' | Set-Content (Join-Path $OutputRoot 'CollectionManifest.json')
                '[{"Name":"DVLAB"}]' | Set-Content (Join-Path $OutputRoot 'synthetic.json')
                [PSCustomObject]@{ Status = 'Completed'; ManifestPath = 'CollectionManifest.json'; FailureMessage = $null }
            }
            try {
                $result = Start-SdnDataCollection -ComputerName DVLAB-S1-N01 -OutputDirectory $TestDrive -IncludeStructuredDiagnostics
                $result.Status | Should -Be Completed
                $manifest = Get-Content $result.ManifestPath -Raw | ConvertFrom-Json
                $manifest.Nodes[0].Node | Should -Be DVLAB-S1-N01
                $result.OutputRoot | Should -Be (Join-Path (Split-Path $result.OutputRoot -Parent) 'StructuredDiagnostics')
                (Get-Content (Join-Path $result.OutputRoot 'DVLAB-S1-N01\synthetic.json') -Raw | ConvertFrom-Json).Name |
                    Should -Be DVLAB
                Should -Invoke Get-SdnInfrastructureInfo -Times 0
                Should -Invoke Confirm-IsServer -ModuleName SdnDiag.StructuredDiagnostics -Times 1
                Should -Invoke Invoke-PSRemoteCommand -ModuleName SdnDiag.StructuredDiagnostics -Times 0
            }
            finally {
                $Global:SdnDiagnostics.Config.Role = $savedRoles
            }
        }
    }
}
