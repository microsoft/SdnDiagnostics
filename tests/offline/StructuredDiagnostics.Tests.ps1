Describe 'SdnDiag.StructuredDiagnostics - collector engine' {
    InModuleScope SdnDiag.StructuredDiagnostics.Collectors {
        BeforeAll {
            $script:originalCatalog = $script:structuredDiagnosticCollectorCatalog
        }
        BeforeEach {
            Mock Trace-Output -RemoveParameterType Level {}
            Mock Trace-Exception {}
            $script:structuredDiagnosticCollectorCatalog = @{
                Groups = @(@{
                    Id = 'Host'
                    TimeoutSeconds = 300
                    Collectors = @(@{
                        Id = 'Test-Record'
                        RelativePath = 'Host\record.json'
                        Collect = { [PSCustomObject]@{ Name = 'DVLAB-S1-N01'; Values = @(1, 2) } }
                    })
                })
            }
        }
        AfterAll {
            $script:structuredDiagnosticCollectorCatalog = $script:originalCatalog
        }

        It 'Writes a singleton as a JSON array with no UTF-8 BOM' {
            $result = Invoke-StructuredDiagnosticCollectorGroup -GroupId Host -OutputRoot $TestDrive -Format Json
            $result.Status | Should -Be Success
            $path = Join-Path $TestDrive 'Host\record.json'
            $text = Get-Content -LiteralPath $path -Raw
            $text.TrimStart().StartsWith('[') | Should -BeTrue
            ($text | ConvertFrom-Json).Name | Should -Be 'DVLAB-S1-N01'
            [System.IO.File]::ReadAllBytes($path)[0] | Should -Be 91
            $result.RecordCount | Should -Be 1
        }

        It 'Writes empty JSON results as an empty array' {
            $script:structuredDiagnosticCollectorCatalog.Groups[0].Collectors[0].Collect = {}
            $result = Invoke-StructuredDiagnosticCollectorGroup -GroupId Host -OutputRoot $TestDrive -Format Json
            $result.RecordCount | Should -Be 0
            (Get-Content (Join-Path $TestDrive 'Host\record.json') -Raw).Trim() -replace '\s', '' | Should -Be '[]'
        }

        It 'Writes one JSON object per NDJSON line' {
            $script:structuredDiagnosticCollectorCatalog.Groups[0].Collectors[0].Collect = {
                [PSCustomObject]@{ Name = 'DVLAB-S1-N01' }
                [PSCustomObject]@{ Name = 'DVLAB-S1-N02' }
            }
            $result = Invoke-StructuredDiagnosticCollectorGroup -GroupId Host -OutputRoot $TestDrive -Format Ndjson
            $lines = @(Get-Content (Join-Path $TestDrive 'Host\record.json'))
            $lines.Count | Should -Be 2
            ($lines[1] | ConvertFrom-Json).Name | Should -Be 'DVLAB-S1-N02'
            $result.RecordCount | Should -Be 2
        }

        It 'Recursively excludes catalog properties' {
            $result = ConvertTo-StructuredDiagnosticRecord -InputObject ([PSCustomObject]@{
                Name = 'DVLAB'
                Nested = [PSCustomObject]@{ ParentAdapter = 'excluded'; CimSession = 'excluded'; Value = 42 }
            }) -ExcludedProperties ParentAdapter
            $result.Nested.PSObject.Properties.Name | Should -Not -Contain ParentAdapter
            $result.Nested.PSObject.Properties.Name | Should -Not -Contain CimSession
            $result.Nested.Value | Should -Be 42
        }

        It 'Uses the supported exclusion key for VM adapter isolation' {
            $collector = $script:originalCatalog.Groups.Collectors | Where-Object Id -eq 'Get-VMNetworkAdapterIsolation'
            $collector.ExcludedProperties | Should -Contain ParentAdapter
            $collector.ContainsKey('Exclude') | Should -BeFalse
        }

        It 'Skips event and setup collectors unless IncludeLogs is set' {
            $script:structuredDiagnosticCollectorCatalog.Groups[0].Collectors = @(
                @{ Id = 'Event'; Kind = 'Event'; RelativePath = 'Host\events.json'; LogName = 'Test'; Collect = { throw 'Must not run' } }
                @{ Id = 'Setup'; Kind = 'FileSet'; RequiresLogs = $true; RelativePath = 'Host\setup'; Collect = { throw 'Must not run' } }
            )
            Mock Get-StructuredDiagnosticEvent { throw 'Must not run' }
            $results = @(Invoke-StructuredDiagnosticCollectorGroup -GroupId Host -OutputRoot $TestDrive -Format Json)
            $results.Count | Should -Be 2
            @($results | Where-Object Status -ne Skipped).Count | Should -Be 0
            Should -Invoke Get-StructuredDiagnosticEvent -Times 0
        }

        It 'Passes the requested date range to events without AllEvents' {
            $script:structuredDiagnosticCollectorCatalog.Groups[0].Collectors = @(
                @{ Id = 'Event'; Kind = 'Event'; RelativePath = 'Host\events.json'; LogName = 'DVLAB-Events'; MaximumBytes = 10MB }
            )
            Mock Get-StructuredDiagnosticEvent { [PSCustomObject]@{ Id = 1 } }
            $from = [datetime]'2026-01-01T00:00:00Z'
            $to = $from.AddHours(1)
            $result = Invoke-StructuredDiagnosticCollectorGroup -GroupId Host -OutputRoot $TestDrive -Format Json -IncludeLogs -FromDate $from -ToDate $to
            $result.Status | Should -Be Success
            Should -Invoke Get-StructuredDiagnosticEvent -Times 1 -ParameterFilter {
                $FromDate -eq [datetime]'2026-01-01T00:00:00Z' -and $ToDate -eq [datetime]'2026-01-01T01:00:00Z' -and -not $AllEvents
            }
        }

        It 'Surfaces a truncated artifact as partial success and enforces the exact byte cap' {
            $script:structuredDiagnosticCollectorCatalog.Groups[0].Collectors = @(
                @{ Id = 'Text'; Kind = 'Text'; RelativePath = 'Host\text.txt'; MaximumBytes = 5; Collect = { 'abc'; 'def' } }
            )
            $result = Invoke-StructuredDiagnosticCollectorGroup -GroupId Host -OutputRoot $TestDrive -Format Json
            $result.Status | Should -Be PartialSuccess
            $result.Truncated | Should -BeTrue
            (Get-Item (Join-Path $TestDrive 'Host\text.txt')).Length | Should -BeLessOrEqual 5
            $result.RecordCount | Should -Be 1
        }

        It 'Preserves records written before a collector fails' {
            $script:structuredDiagnosticCollectorCatalog.Groups[0].Collectors[0].Collect = {
                [PSCustomObject]@{ Name = 'DVLAB' }
                throw 'Mock collector failure'
            }
            $result = Invoke-StructuredDiagnosticCollectorGroup -GroupId Host -OutputRoot $TestDrive -Format Json -ErrorAction SilentlyContinue
            $result.Status | Should -Be PartialSuccess
            $result.RecordCount | Should -Be 1
            (Get-Content (Join-Path $TestDrive 'Host\record.json') -Raw | ConvertFrom-Json).Name | Should -Be DVLAB
        }

        It 'Does not claim an artifact for an unavailable command' {
            $script:structuredDiagnosticCollectorCatalog.Groups[0].Collectors[0].CommandName = 'Get-DVLABMissingCommand'
            $result = Invoke-StructuredDiagnosticCollectorGroup -GroupId Host -OutputRoot $TestDrive -Format Json
            $result.Status | Should -Be Unavailable
            $result.OutputArtifacts.Count | Should -Be 0
        }

        It 'Skips an unavailable Get-StorageNetworkIntent command and continues collecting' {
            $collector = $script:originalCatalog.Groups.Collectors | Where-Object Id -eq 'Get-StorageNetworkIntent'
            $group = $script:structuredDiagnosticCollectorCatalog.Groups[0]
            $group.Id = 'NetworkATC'
            $group.Collectors = @($collector) + $group.Collectors
            Mock Get-Command {} -ParameterFilter { $Name -eq 'Get-StorageNetworkIntent' }

            $outputRoot = Join-Path $TestDrive 'missing-storage-network-intent'
            $results = @(Invoke-StructuredDiagnosticCollectorGroup -GroupId NetworkATC -OutputRoot $outputRoot -Format Json)
            $results.Count | Should -Be 2
            $results[0].CollectorId | Should -Be 'Get-StorageNetworkIntent'
            $results[0].Status | Should -Be Unavailable
            $results[0].FailureMessage | Should -Be 'Command Get-StorageNetworkIntent is unavailable.'
            $results[0].RecordCount | Should -Be 0
            $results[0].OutputArtifacts.Count | Should -Be 0
            Test-Path -LiteralPath (Join-Path $outputRoot $collector.RelativePath) | Should -BeFalse
            $results[1].Status | Should -Be Success
            $results[1].RecordCount | Should -Be 1
            (Get-Content (Join-Path $outputRoot $results[1].RelativePath) -Raw | ConvertFrom-Json).Name | Should -Be 'DVLAB-S1-N01'
            Should -Invoke Get-Command -Times 1 -Exactly -ParameterFilter { $Name -eq 'Get-StorageNetworkIntent' }
            Should -Invoke Trace-Exception -Times 0
        }

        It 'Rejects an inverted time window before starting jobs' {
            Mock Start-Job { throw 'Must not run' }
            { Invoke-StructuredDiagnosticCollection -OutputRoot $TestDrive -CollectionId DVLAB -ModuleVersion '1.0' -Format Json `
                -FromDate ([datetime]'2026-01-02') -ToDate ([datetime]'2026-01-01') } | Should -Throw '*FromDate*'
            Should -Invoke Start-Job -Times 0
        }

        It 'Writes nested manifest artifact metadata without flattening it' {
            Mock Start-Job { [PSCustomObject]@{ State = 'Completed' } }
            Mock Receive-Job -RemoveParameterType Job {
                [PSCustomObject]@{
                    CollectorId = 'Test-Record'; Status = 'Success'; RecordCount = 1
                    OutputArtifacts = @([PSCustomObject]@{ RelativePath = 'Host\record.json'; Status = 'Success'; RecordCount = 1 })
                }
            }
            Mock Remove-Job -RemoveParameterType Job {}
            $output = @(Invoke-StructuredDiagnosticCollection -OutputRoot $TestDrive -CollectionId DVLAB -ModuleVersion '1.0' -Format Json `
                -FromDate (Get-Date).AddHours(-1) -ToDate (Get-Date) -EmitProgressEvents)
            $progressEvents = @($output | Where-Object StructuredDiagnosticProgressEvent)
            $result = $output | Where-Object { -not $_.StructuredDiagnosticProgressEvent } | Select-Object -Last 1
            $result.Status | Should -Be Completed
            $progressEvents[0].CompletedCount | Should -Be 0
            $progressEvents[-1].CompletedCount | Should -Be 1
            $progressEvents[-1].TotalCount | Should -Be 1
            $progressEvents[-1].RemainingGroups.Count | Should -Be 0
            $manifest = Get-Content (Join-Path $TestDrive 'CollectionManifest.json') -Raw | ConvertFrom-Json
            $manifest.Groups[0].Collectors[0].OutputArtifacts[0].RelativePath | Should -Be 'Host\record.json'
            $manifest.SchemaVersion | Should -Be 1
        }

        It 'Fails a collection when all groups are unavailable' {
            $script:structuredDiagnosticCollectorCatalog.Groups[0].Condition = { $false }
            Mock Start-Job { throw 'Must not run' }
            $result = Invoke-StructuredDiagnosticCollection -OutputRoot $TestDrive -CollectionId DVLAB -ModuleVersion '1.0' -Format Json `
                -FromDate (Get-Date).AddHours(-1) -ToDate (Get-Date)
            $result.Status | Should -Be Failed
            Should -Invoke Start-Job -Times 0
        }

        It 'Retains completed collector results when a group times out' {
            $script:structuredDiagnosticCollectorCatalog.Groups[0].TimeoutSeconds = -1
            $script:structuredDiagnosticCollectorCatalog.Groups[0].Collectors += @{ Id = 'NotFinished'; RelativePath = 'Host\missing.json' }
            Mock Start-Job { [PSCustomObject]@{ State = 'Running' } }
            Mock Stop-Job -RemoveParameterType Job {}
            Mock Receive-Job -RemoveParameterType Job { [PSCustomObject]@{ CollectorId = 'Test-Record'; Status = 'Success'; RecordCount = 1; OutputArtifacts = @('Host\record.json') } }
            Mock Remove-Job -RemoveParameterType Job {}
            $result = Invoke-StructuredDiagnosticCollection -OutputRoot $TestDrive -CollectionId DVLAB -ModuleVersion '1.0' -Format Json `
                -FromDate (Get-Date).AddHours(-1) -ToDate (Get-Date)
            $manifest = Get-Content (Join-Path $TestDrive 'CollectionManifest.json') -Raw | ConvertFrom-Json
            $result.Status | Should -Be CompletedWithFailures
            $manifest.Groups[0].Status | Should -Be TimedOut
            $manifest.Groups[0].Collectors[0].RecordCount | Should -Be 1
            $manifest.Groups[0].Collectors[1].OutputArtifacts.Count | Should -Be 0
            Should -Invoke Receive-Job -Times 1
        }

        It 'Maps performance duration to documented relative buckets' {
            $from = [datetime]'2026-01-01'
            Get-StructuredDiagnosticPerformanceTimeFrame -FromDate $from -ToDate $from.AddHours(1) | Should -Be LastHour
            Get-StructuredDiagnosticPerformanceTimeFrame -FromDate $from -ToDate $from.AddHours(4) | Should -Be LastDay
            Get-StructuredDiagnosticPerformanceTimeFrame -FromDate $from -ToDate $from.AddDays(7) | Should -Be LastWeek
        }

        It 'Copies exactly the bounded tail of a setup log' {
            $source = Join-Path $TestDrive 'setup-source.log'
            $destination = Join-Path $TestDrive 'setup-tail.log'
            [System.IO.File]::WriteAllBytes($source, [byte[]](0..255))
            $result = Copy-StructuredDiagnosticBoundedFile -SourcePath $source -DestinationPath $destination -MaximumBytes 64
            $bytes = [System.IO.File]::ReadAllBytes($destination)
            $bytes.Length | Should -Be 64
            $bytes[0] | Should -Be 192
            $bytes[63] | Should -Be 255
            $result.CopiedBytes | Should -Be 64
            $result.Truncated | Should -BeTrue
        }

        It 'Loads the collectors and writer in a fresh process without CSSTools' {
            $modulePath = (Get-Module SdnDiag.StructuredDiagnostics.Collectors -All | Select-Object -First 1).Path
            $job = Start-Job -ScriptBlock {
                param($modulePath, $outputPath)
                Import-Module $modulePath -ErrorAction Stop
                $writer = Open-StructuredDiagnosticArtifactWriter -Path $outputPath -Format Json
                Write-StructuredDiagnosticArtifactRecord -Writer $writer -Record ([PSCustomObject]@{ Name = 'DVLAB' })
                Close-StructuredDiagnosticArtifactWriter -Writer $writer
                Trace-Output -Level Verbose -Message 'Offline module bootstrap verification.'
                (Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json).Name
            } -ArgumentList $modulePath, (Join-Path $TestDrive 'child-process.json')
            try {
                $null = $job | Wait-Job -Timeout 30
                $job.State | Should -Be Completed
                Receive-Job -Job $job -ErrorAction Stop | Should -Be DVLAB
            }
            finally {
                Stop-Job -Job $job
                Remove-Job -Job $job -Force
            }
        }
    }
}

Describe 'SdnDiag.StructuredDiagnostics - target resolution' {
    InModuleScope SdnDiag.StructuredDiagnostics {
        BeforeAll {
            $script:createdClusterNodeStub = -not (Get-Command Get-ClusterNode -ErrorAction SilentlyContinue)
            if ($script:createdClusterNodeStub) {
                function global:Get-ClusterNode { [CmdletBinding()] param() }
            }
        }
        AfterAll {
            if ($script:createdClusterNodeStub) {
                Remove-Item -LiteralPath 'Function:\global:Get-ClusterNode'
            }
        }
        BeforeEach {
            Mock Trace-Output -RemoveParameterType Level {}
            Mock Trace-Exception {}
            Mock Test-Path -ParameterFilter { $LiteralPath -eq 'HKLM:\Cluster' } { $true }
            Mock Get-ClusterNode {
                @(
                    [PSCustomObject]@{ Name = 'DVLAB-S1-N01'; State = 'Up' }
                    [PSCustomObject]@{ Name = 'DVLAB-S1-N02'; State = 'Up' }
                    [PSCustomObject]@{ Name = 'DVLAB-S1-N03'; State = 'Down' }
                )
            }
        }

        It 'Preserves all explicit targets and removes duplicate names without cluster discovery' {
            $targets = @(Get-StructuredDiagnosticTarget -ComputerName DVLAB-S1-N02,DVLAB-S1-N01,DVLAB-S1-N02)
            $targets | Should -Be @('DVLAB-S1-N02', 'DVLAB-S1-N01')
            Should -Invoke Test-Path -Times 0 -ParameterFilter { $LiteralPath -eq 'HKLM:\Cluster' }
            Should -Invoke Get-ClusterNode -Times 0
        }

        It 'Resolves every configured cluster node including unavailable nodes' {
            $targets = @(Get-StructuredDiagnosticTarget)
            $targets | Should -Be @('DVLAB-S1-N01', 'DVLAB-S1-N02', 'DVLAB-S1-N03')
            Should -Invoke Get-ClusterNode -Times 1
        }

        It 'Uses localhost only when the machine is not a configured cluster member' {
            Mock Test-Path -ParameterFilter { $LiteralPath -eq 'HKLM:\Cluster' } { $false }
            @(Get-StructuredDiagnosticTarget) | Should -Be @($env:COMPUTERNAME)
            Should -Invoke Get-ClusterNode -Times 0
        }

        It 'Surfaces failed cluster enumeration without falling back to localhost' {
            Mock Get-ClusterNode { throw 'DVLAB cluster unavailable' }
            { Get-StructuredDiagnosticTarget -ErrorAction Stop } | Should -Throw '*DVLAB cluster unavailable*'
            Should -Invoke Trace-Exception -Times 1
        }

        It 'Rejects an empty configured cluster rather than collecting only localhost' {
            Mock Get-ClusterNode { @() }
            { Get-StructuredDiagnosticTarget -ErrorAction Stop } | Should -Throw '*returned no host nodes*'
            Should -Invoke Trace-Exception -Times 1
        }

        It 'Routes every resolved cluster node through the public entry point without NC discovery' {
            $savedRoles = $Global:SdnDiagnostics.Config.Role
            Mock Get-WorkingDirectory -ModuleName SdnDiagnostics { $TestDrive }
            Mock Trace-Output -ModuleName SdnDiagnostics -RemoveParameterType Level {}
            Mock Get-SdnInfrastructureInfo -ModuleName SdnDiagnostics { throw 'Must not discover NC' }
            Mock Get-SdnServiceFabricClusterManifest -ModuleName SdnDiagnostics { throw 'Must not query Service Fabric' }
            Mock Invoke-StructuredDiagnostics -ModuleName SdnDiagnostics { [PSCustomObject]@{ Status = 'Completed' } }
            try {
                $Global:SdnDiagnostics.Config.Role = @('Common')
                $result = Start-SdnDataCollection -Role Server -OutputDirectory $TestDrive -IncludeStructuredDiagnostics
                $result.Status | Should -Be Completed
                Should -Invoke Invoke-StructuredDiagnostics -ModuleName SdnDiagnostics -Times 1 -ParameterFilter {
                    $ComputerName.Count -eq 3 -and $ComputerName -contains 'DVLAB-S1-N01' -and
                    $ComputerName -contains 'DVLAB-S1-N02' -and $ComputerName -contains 'DVLAB-S1-N03'
                }
                Should -Invoke Get-SdnInfrastructureInfo -ModuleName SdnDiagnostics -Times 0
                Should -Invoke Get-SdnServiceFabricClusterManifest -ModuleName SdnDiagnostics -Times 0
            }
            finally {
                $Global:SdnDiagnostics.Config.Role = $savedRoles
            }
        }
    }
}

Describe 'SdnDiag.StructuredDiagnostics - internal collection' {
    InModuleScope SdnDiag.StructuredDiagnostics {
        BeforeEach {
            Mock Trace-Output -RemoveParameterType Level {}
            Mock Trace-Exception {}
            $script:collectionOutput = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            $script:collectionId = Split-Path -Path $script:collectionOutput -Leaf
            Mock Get-WorkingDirectory { $TestDrive }
            Mock Initialize-DataCollection -RemoveParameterType Role {
                $null = New-Item -Path $FilePath -ItemType Directory -Force
                $true
            }
            Mock Test-ComputerNameIsLocal { $true }
            Mock Confirm-IsServer {}
            Mock Get-SdnInfrastructureInfo { throw 'Must not discover SDN' }
            Mock Get-EnvironmentRole { throw 'Must not infer SDN roles' }
            Mock Invoke-StructuredDiagnosticCollection {
                $null = New-Item -Path $OutputRoot -ItemType Directory -Force
                '{"Status":"Completed"}' | Set-Content (Join-Path $OutputRoot 'CollectionManifest.json')
                [PSCustomObject]@{ Node = 'DVLAB-S1-N01'; Status = 'Completed'; ManifestPath = 'CollectionManifest.json'; FailureMessage = $null }
            }
            $script:structuredModuleUnderTest = Get-Module SdnDiag.StructuredDiagnostics -All | Select-Object -First 1
            Mock Import-Module -ParameterFilter { $Name -like '*\modules\SdnDiag.StructuredDiagnostics.psm1' } {
                $script:structuredModuleUnderTest
            }
            $script:remoteScriptBlock = $null
            $script:remoteArgumentList = $null
            $script:localScriptBlock = $null
            $script:localArgumentList = $null
            Mock Invoke-PSRemoteCommand {
                $script:remoteScriptBlock = $ScriptBlock
                $script:remoteArgumentList = $ArgumentList
                [PSCustomObject]@{ Name = 'SdnDiag-DVLAB' }
            }
            Mock Start-Job {
                $script:localScriptBlock = $ScriptBlock
                $script:localArgumentList = $ArgumentList
                [PSCustomObject]@{ Name = 'SdnDiag-Local-DVLAB' }
            }
            Mock Wait-PSJob {
                if ($script:remoteScriptBlock) {
                    & $script:remoteScriptBlock @script:remoteArgumentList
                }
                if ($script:localScriptBlock) {
                    & $script:localScriptBlock @script:localArgumentList
                }
            }
            Mock Copy-FileFromRemoteComputer {
                Copy-Item -Path $Path -Destination $Destination.FullName -Recurse -Force
            }
            Mock Clear-SdnWorkingDirectory {}
        }

        It 'Collects locally without SDN discovery, role detection or WinRM' {
            $result = Invoke-StructuredDiagnostics -ComputerName DVLAB-S1-N01 -OutputDirectory $script:collectionOutput
            $result.Status | Should -Be Completed
            $result.CollectionId | Should -Be $script:collectionId
            $result.OutputRoot | Should -Be (Join-Path $script:collectionOutput 'StructuredDiagnostics')
            (Split-Path $result.ManifestPath -Leaf) | Should -Be 'ClusterCollectionManifest.json'
            Test-Path (Join-Path $result.OutputRoot 'DVLAB-S1-N01\CollectionManifest.json') | Should -BeTrue
            $manifest = Get-Content $result.ManifestPath -Raw | ConvertFrom-Json
            $manifest.Nodes.Count | Should -Be 1
            $manifest.Nodes[0].Node | Should -Be DVLAB-S1-N01
            Should -Invoke Get-SdnInfrastructureInfo -Times 0
            Should -Invoke Get-EnvironmentRole -Times 0
            Should -Invoke Invoke-PSRemoteCommand -Times 0
            Should -Invoke Start-Job -Times 1
            Should -Invoke Wait-PSJob -Times 1
            Should -Invoke Copy-FileFromRemoteComputer -Times 0
            Should -Invoke Clear-SdnWorkingDirectory -Times 0
        }

        It 'Passes dates, format, module version and log selection to the engine' {
            $from = [datetime]'2026-01-01T00:00:00Z'
            $result = Invoke-StructuredDiagnostics -OutputDirectory $script:collectionOutput `
                -Format Ndjson -IncludeLogs -FromDate $from -ToDate $from.AddHours(2)
            $result.Status | Should -Be Completed
            Should -Invoke Invoke-StructuredDiagnosticCollection -Times 1 -ParameterFilter {
                $CollectionId -eq $script:collectionId -and $IncludeLogs -and $Format -eq 'Ndjson' -and
                -not [string]::IsNullOrEmpty($ModuleVersion) -and
                $FromDate -eq [datetime]'2026-01-01T00:00:00Z' -and $ToDate -eq [datetime]'2026-01-01T02:00:00Z'
            }
        }

        It 'Does not run local collectors when the Hyper-V host check fails' {
            Mock Confirm-IsServer { throw 'DVLAB target is not a Hyper-V host' }
            { Invoke-StructuredDiagnostics -ComputerName DVLAB-S1-N01 -OutputDirectory $script:collectionOutput -ErrorAction Stop } |
                Should -Throw '*not a Hyper-V host*'
            Should -Invoke Invoke-StructuredDiagnosticCollection -Times 0
            Should -Invoke Get-SdnInfrastructureInfo -Times 0
        }

        It 'Does not run remote collectors when the Hyper-V host check fails' {
            Mock Test-ComputerNameIsLocal { $false }
            Mock Confirm-IsServer { throw 'DVLAB target is not a Hyper-V host' }
            { Invoke-StructuredDiagnostics -ComputerName DVLAB-NC01 -OutputDirectory $script:collectionOutput -ErrorAction Stop } |
                Should -Throw '*not a Hyper-V host*'
            Should -Invoke Invoke-StructuredDiagnosticCollection -Times 0
            Should -Invoke Copy-FileFromRemoteComputer -Times 0
        }

        It 'Defaults to the local computer without optional logs' {
            $result = Invoke-StructuredDiagnostics -OutputDirectory $script:collectionOutput
            $result.Nodes[0].Node | Should -Be $env:COMPUTERNAME
            Should -Invoke Invoke-StructuredDiagnosticCollection -Times 1 -ParameterFilter { -not $IncludeLogs -and $Format -eq 'Json' }
        }

        It 'Starts remote collection before collecting from the local computer' {
            $script:startOrder = [System.Collections.ArrayList]::new()
            Mock Test-ComputerNameIsLocal { $ComputerName -eq 'DVLAB-S1-N01' }
            Mock Invoke-PSRemoteCommand {
                [void]$script:startOrder.Add('RemoteJob')
                $script:remoteScriptBlock = $ScriptBlock
                $script:remoteArgumentList = $ArgumentList
                [PSCustomObject]@{ Name = 'SdnDiag-DVLAB' }
            }
            Mock Start-Job {
                [void]$script:startOrder.Add('LocalJob')
                $script:localScriptBlock = $ScriptBlock
                $script:localArgumentList = $ArgumentList
                [PSCustomObject]@{ Name = 'SdnDiag-Local-DVLAB' }
            }
            Mock Wait-PSJob {
                [void]$script:startOrder.Add('Wait')
                $progressJobs = @(
                    [PSCustomObject]@{
                        Output = @(
                            [PSCustomObject]@{
                                StructuredDiagnosticProgressEvent = $true; EventId = 'remote-host'
                                Node = 'DVLAB-S1-N02'; PSComputerName = 'DVLAB-S1-N02'; GroupId = 'Host'
                                Status = 'Success'; CompletedCount = 1; TotalCount = 17
                                RemainingGroups = @('Cluster', 'HyperV', 'SMB', 'Firewall', 'VM')
                            }
                            [PSCustomObject]@{
                                StructuredDiagnosticProgressEvent = $true; EventId = 'remote-hyperv'
                                Node = 'DVLAB-S1-N02'; PSComputerName = 'DVLAB-S1-N02'; GroupId = 'HyperV'
                                Status = 'Success'; CompletedCount = 2; TotalCount = 17
                                RemainingGroups = @('Cluster', 'HyperV', 'SMB', 'Firewall', 'Host', 'VM')
                            }
                        )
                        ChildJobs = @([PSCustomObject]@{
                            State = 'Running'; Location = 'DVLAB-S1-N02'; Output = @()
                        })
                    }
                    [PSCustomObject]@{ ChildJobs = @([PSCustomObject]@{
                        State = 'Running'; Location = 'localhost'
                        Output = @(
                            [PSCustomObject]@{
                                StructuredDiagnosticProgressEvent = $true; EventId = 'local-host'
                                Node = 'DVLAB-S1-N01'; GroupId = 'Host'; Status = 'Success'
                                CompletedCount = 1; TotalCount = 17; RemainingGroups = @('Cluster', 'SMB')
                            }
                            [PSCustomObject]@{
                                StructuredDiagnosticProgressEvent = $true; EventId = 'local-tcpip'
                                Node = 'DVLAB-S1-N01'; GroupId = 'TcpIp'; Status = 'Success'
                                CompletedCount = 2; TotalCount = 17; RemainingGroups = @('Cluster', 'SMB')
                            }
                            [PSCustomObject]@{
                                StructuredDiagnosticProgressEvent = $true; EventId = 'local-cluster'
                                Node = 'DVLAB-S1-N01'; GroupId = 'Cluster'; Status = 'PartialSuccess'
                                CompletedCount = 3; TotalCount = 17; RemainingGroups = @('Cluster', 'SMB')
                            }
                        )
                    }) }
                )
                $progressUpdateState = @{}
                & $ProgressUpdateScript $progressJobs $progressUpdateState
                & $ProgressUpdateScript $progressJobs $progressUpdateState
                $script:renderedProgress = & $ProgressStatusScript $progressJobs
                $script:renderedPercent = & $ProgressPercentScript $progressJobs
                & $script:remoteScriptBlock @script:remoteArgumentList
                & $script:localScriptBlock @script:localArgumentList
            }
            Mock Invoke-StructuredDiagnosticCollection {
                $scope = if ($OutputRoot -like '*StructuredDiagnostics_Staging*') { 'RemoteCollector' } else { 'LocalCollector' }
                [void]$script:startOrder.Add($scope)
                $null = New-Item -Path $OutputRoot -ItemType Directory -Force
                '{"Status":"Completed"}' | Set-Content (Join-Path $OutputRoot 'CollectionManifest.json')
                [PSCustomObject]@{ Node = 'DVLAB'; Status = 'Completed'; ManifestPath = 'CollectionManifest.json'; FailureMessage = $null }
            }

            $result = Invoke-StructuredDiagnostics -ComputerName DVLAB-S1-N01,DVLAB-S1-N02 `
                -OutputDirectory $script:collectionOutput

            $result.Status | Should -Be Completed
            (($script:startOrder | Select-Object -First 3) -join ',') | Should -Be 'RemoteJob,LocalJob,Wait'
            $script:renderedProgress | Should -Be (
                'DVLAB-S1-N02 2/17 groups (Cluster, HyperV, +4 more); ' +
                'DVLAB-S1-N01 3/17 groups (Cluster, SMB)'
            )
            $script:renderedPercent | Should -Be 14.71
            Should -Invoke Trace-Output -Times 5 -ParameterFilter {
                $Message -like 'Completed structured diagnostics group *'
            }
            Should -Invoke Trace-Output -Times 2 -ParameterFilter {
                $ComputerName -eq 'DVLAB-S1-N02' -and
                $Message -like 'Completed structured diagnostics group *'
            }
            Should -Invoke Trace-Output -Times 3 -ParameterFilter {
                $ComputerName -eq 'DVLAB-S1-N01' -and
                $Message -like 'Completed structured diagnostics group *'
            }
            Should -Invoke Trace-Output -Times 1 -ParameterFilter {
                $ComputerName -eq 'DVLAB-S1-N01' -and
                $Message -eq 'Completed structured diagnostics group Cluster (3/17, PartialSuccess)'
            }
        }

        It 'Uses shared remote execution, copy and cleanup helpers with credentials' {
            Mock Test-ComputerNameIsLocal { $false }
            $script:rootModuleUnderTest = Microsoft.PowerShell.Core\Get-Module SdnDiagnostics -All | Select-Object -First 1
            $script:getRootModuleCallCount = 0
            Mock Get-Module -ParameterFilter { $Name -eq 'SdnDiagnostics' } {
                $script:getRootModuleCallCount++
                if ($script:getRootModuleCallCount -eq 1) {
                    $script:rootModuleUnderTest
                }
            }
            Mock Import-Module -ParameterFilter { $Name -eq 'SdnDiagnostics' } {
                $script:rootModuleUnderTest
            }
            $credential = [pscredential]::new('DVLAB\operator', (ConvertTo-SecureString 'mock-only' -AsPlainText -Force))
            $result = Invoke-StructuredDiagnostics -ComputerName DVLAB-S1-N01 `
                -OutputDirectory $script:collectionOutput -Credential $credential
            $result.Status | Should -Be Completed
            Should -Invoke Invoke-PSRemoteCommand -Times 1 -ParameterFilter {
                $Credential.UserName -eq 'DVLAB\operator' -and $ImportModuleOnRemoteSession -and $AsJob -and -not $PassThru
            }
            Should -Invoke Wait-PSJob -Times 1 -ParameterFilter {
                $Name -contains 'SdnDiag-DVLAB' -and $Activity -eq 'Structured diagnostics' -and
                    $ExecutionTimeOut -eq 1800 -and -not $ProgressMessageInterval -and
                    $null -ne $ProgressStatusScript -and $null -ne $ProgressPercentScript -and
                    $null -ne $ProgressUpdateScript -and $null -eq $ProgressMessageScript -and $ShowProgress
            }
            Should -Invoke Import-Module -Times 1 -ParameterFilter {
                $Name -like '*\modules\SdnDiag.StructuredDiagnostics.psm1' -and $PassThru
            }
            Should -Invoke Import-Module -Times 1 -ParameterFilter {
                $Name -eq 'SdnDiagnostics' -and $PassThru
            }
            $script:remoteScriptBlock.ToString() | Should -Match '& \$structuredModule'
            Should -Invoke Copy-FileFromRemoteComputer -Times 1 -ParameterFilter {
                $Credential.UserName -eq 'DVLAB\operator' -and $ComputerName -contains 'DVLAB-S1-N01'
            }
            Should -Invoke Clear-SdnWorkingDirectory -Times 1 -ParameterFilter {
                $Credential.UserName -eq 'DVLAB\operator' -and
                $Path -contains (Join-Path $TestDrive "StructuredDiagnostics_Staging\$script:collectionId")
            }
        }

        It 'Retains staging when remote copy fails' {
            Mock Test-ComputerNameIsLocal { $false }
            Mock Copy-FileFromRemoteComputer { throw 'DVLAB copy failed' }
            { Invoke-StructuredDiagnostics -ComputerName DVLAB-S1-N01 -OutputDirectory $script:collectionOutput -ErrorAction Stop } |
                Should -Throw '*every requested computer*'
            Should -Invoke Clear-SdnWorkingDirectory -Times 0
            $manifest = Get-Content (Join-Path $script:collectionOutput 'StructuredDiagnostics\ClusterCollectionManifest.json') -Raw |
                ConvertFrom-Json
            $manifest.Status | Should -Be Failed
            $manifest.Nodes[0].FailureMessage | Should -Match 'copy failed'
        }

        It 'Does not clean staging when the retrieved manifest is missing' {
            Mock Test-ComputerNameIsLocal { $false }
            Mock Copy-FileFromRemoteComputer {}
            { Invoke-StructuredDiagnostics -ComputerName DVLAB-S1-N01 -OutputDirectory $script:collectionOutput -ErrorAction Stop } |
                Should -Throw '*every requested computer*'
            Should -Invoke Clear-SdnWorkingDirectory -Times 0
        }

        It 'Reports partial structured collection' {
            Mock Invoke-StructuredDiagnosticCollection {
                [PSCustomObject]@{ Status = 'CompletedWithFailures'; ManifestPath = 'CollectionManifest.json'; FailureMessage = $null }
            }
            $result = Invoke-StructuredDiagnostics -ComputerName DVLAB-S1-N01 -OutputDirectory $script:collectionOutput
            $result.Status | Should -Be CompletedWithFailures
        }

        It 'Rejects invalid dates and unsafe or colliding directory names before contacting nodes' {
            { Invoke-StructuredDiagnostics -FromDate ([datetime]'2026-01-02') -ToDate ([datetime]'2026-01-01') } | Should -Throw '*FromDate*'
            { Invoke-StructuredDiagnostics -ComputerName '..' -OutputDirectory $script:collectionOutput } | Should -Throw '*directory name*'
            { Invoke-StructuredDiagnostics -ComputerName DVLAB,DVLAB. -OutputDirectory $script:collectionOutput } | Should -Throw '*directory name*'
            Should -Invoke Invoke-PSRemoteCommand -Times 0
            Should -Invoke Initialize-DataCollection -Times 0
        }

        It 'Reports missing remote output and does not copy or clean' {
            Mock Test-ComputerNameIsLocal { $false }
            Mock Wait-PSJob {}
            { Invoke-StructuredDiagnostics -ComputerName DVLAB-S1-N01 -OutputDirectory $script:collectionOutput -ErrorAction Stop } |
                Should -Throw '*every requested computer*'
            Should -Invoke Copy-FileFromRemoteComputer -Times 0
            Should -Invoke Clear-SdnWorkingDirectory -Times 0
        }

        It 'Batches remote nodes and reports a missing node result as a failure' {
            Mock Test-ComputerNameIsLocal { $false }
            Mock Wait-PSJob {
                $remoteResult = & $script:remoteScriptBlock @script:remoteArgumentList
                $remoteResult | Add-Member -NotePropertyName PSComputerName -NotePropertyValue 'DVLAB-S1-N02' -Force
                $remoteResult
            }
            $result = Invoke-StructuredDiagnostics -ComputerName DVLAB-S1-N01,DVLAB-S1-N02 `
                -OutputDirectory $script:collectionOutput -ErrorAction SilentlyContinue
            $result.Status | Should -Be CompletedWithFailures
            $result.Nodes.Count | Should -Be 2
            $result.Nodes[0].Status | Should -Be Failed
            $result.Nodes[1].Status | Should -Be Completed
            Should -Invoke Invoke-PSRemoteCommand -Times 1 -ParameterFilter {
                $ComputerName.Count -eq 2 -and $ComputerName -contains 'DVLAB-S1-N01' -and $ComputerName -contains 'DVLAB-S1-N02'
            }
            Should -Invoke Clear-SdnWorkingDirectory -Times 1 -ParameterFilter { $ComputerName -contains 'DVLAB-S1-N02' }
        }

        It 'Rejects an existing collection directory before collecting or cleaning' {
            $path = Join-Path $script:collectionOutput 'StructuredDiagnostics'
            $null = New-Item -Path $path -ItemType Directory -Force
            'DVLAB existing data' | Set-Content (Join-Path $path 'keep.txt')
            { Invoke-StructuredDiagnostics -ComputerName DVLAB-S1-N01 -OutputDirectory $script:collectionOutput } |
                Should -Throw '*already exists*'
            Get-Content (Join-Path $path 'keep.txt') | Should -Be 'DVLAB existing data'
            Should -Invoke Invoke-StructuredDiagnosticCollection -Times 0
            Should -Invoke Invoke-PSRemoteCommand -Times 0
            Should -Invoke Clear-SdnWorkingDirectory -Times 0
        }
    }
}
