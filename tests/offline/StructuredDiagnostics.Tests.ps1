Describe 'SdnDiag.StructuredDiagnostics - record normalization' -Tag 'Unit' {
    InModuleScope SdnDiag.StructuredDiagnostics.Collectors {
        It 'Preserves scalar values and honors date formatting in <Container>' -TestCases @(
            @{ Container = 'Dictionary' }
            @{ Container = 'Object' }
            @{ Container = 'Array' }
        ) {
            param($Container)
            $values = [ordered]@{
                Name = 'DVLAB-S1-N01'
                Count = 42
                Enabled = $false
                Missing = $null
                Date = [DateTime]'2026-01-01T01:00:00'
                Offset = [DateTimeOffset]'2026-01-01T01:00:00+02:00'
            }
            switch ($Container) {
                'Dictionary' { $inputObject = $values }
                'Object' { $inputObject = [PSCustomObject]$values }
                'Array' { $inputObject = @($values.Values) }
            }

            $result = ConvertTo-StructuredDiagnosticRecord -InputObject $inputObject
            $formatted = ConvertTo-StructuredDiagnosticRecord -InputObject $inputObject -FormatDateTime
            $index = 0
            foreach ($key in $values.Keys) {
                $actual = if ($Container -eq 'Array') { $result[$index] } else { $result.$key }
                $formattedValue = if ($Container -eq 'Array') { $formatted[$index] } else { $formatted.$key }
                if ($null -eq $values[$key]) {
                    ($null -eq $actual) | Should -BeTrue
                    ($null -eq $formattedValue) | Should -BeTrue
                }
                else {
                    $actual.GetType() | Should -Be $values[$key].GetType()
                    $actual | Should -Be $values[$key]
                    if ($values[$key] -is [DateTime] -or $values[$key] -is [DateTimeOffset]) {
                        $formattedValue | Should -BeOfType [string]
                        $formattedValue | Should -BeExactly $values[$key].ToString('o')
                    }
                    else {
                        $formattedValue.GetType() | Should -Be $values[$key].GetType()
                        $formattedValue | Should -Be $values[$key]
                    }
                }
                $index++
            }
        }

        It 'Preserves empty, singleton, nested, and null array elements' {
            $result = ConvertTo-StructuredDiagnosticRecord -InputObject @(@(), @(42), @(1, 2), $null)
            ($result -is [array]) | Should -BeTrue
            $result.Count | Should -Be 4
            ($result[0] -is [array]) | Should -BeTrue
            $result[0].Count | Should -Be 0
            ($result[1] -is [array]) | Should -BeTrue
            $result[1].Count | Should -Be 1
            $result[1][0] | Should -Be 42
            ($result[2] -is [array]) | Should -BeTrue
            $result[2].Count | Should -Be 2
            $result[2][0] | Should -Be 1
            $result[2][1] | Should -Be 2
            ($null -eq $result[3]) | Should -BeTrue
        }

    }
}

Describe 'SdnDiag.StructuredDiagnostics - cached inventories' -Tag 'Unit' {
    InModuleScope SdnDiag.StructuredDiagnostics.Collectors {
        It 'Caches an empty inventory rather than collecting it again' {
            $cache = @{}
            $first = @(Get-StructuredDiagnosticCachedValue -Cache $cache -Key VirtualMachines -Collect {})
            $second = @(Get-StructuredDiagnosticCachedValue -Cache $cache -Key VirtualMachines -Collect { throw 'Must use the cache' })

            $cache.ContainsKey('VirtualMachines') | Should -BeTrue
            $first.Count | Should -Be 0
            $second.Count | Should -Be 0
        }

        It 'Streams partial inventory records, propagates failure, and retries instead of caching an incomplete inventory' {
            $cache = @{}
            $records = [System.Collections.ArrayList]::new()
            {
                Get-StructuredDiagnosticCachedValue -Cache $cache -Key VirtualMachines -Collect {
                    [PSCustomObject]@{ Name = 'DVLAB-VM01' }
                    throw 'DVLAB inventory interrupted'
                } | ForEach-Object { [void]$records.Add($_) }
            } | Should -Throw '*DVLAB inventory interrupted*'

            $records.Count | Should -Be 1
            $records[0].Name | Should -Be DVLAB-VM01
            $cache.ContainsKey('VirtualMachines') | Should -BeFalse
            $retry = @(Get-StructuredDiagnosticCachedValue -Cache $cache -Key VirtualMachines -Collect {
                [PSCustomObject]@{ Name = 'DVLAB-VM02' }
            })
            $retry.Count | Should -Be 1
            $retry[0].Name | Should -Be DVLAB-VM02
            $cache.ContainsKey('VirtualMachines') | Should -BeTrue
        }
    }
}

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
                    TimeoutSeconds = 600
                    Collectors = @(@{
                        Id = 'Test-Record'
                        RelativePath = 'Host\record.json'
                        Collect = { [PSCustomObject]@{ Name = 'DVLAB-S1-N01'; Values = @(1, 2) } }
                    })
                })
            }
            Mock New-StructuredDiagnosticWorker {
                @{
                    PowerShell = @{ InvocationStateInfo = @{ State = 'Completed' } }
                    Invocation = @{ IsCompleted = $true }
                }
            }
            Mock Start-StructuredDiagnosticWorkerGroup {}
            Mock Remove-StructuredDiagnosticWorker {}
        }
        AfterAll {
            $script:structuredDiagnosticCollectorCatalog = $script:originalCatalog
        }

        It 'Writes a singleton as a JSON array with no UTF-8 BOM' {
            $result = Invoke-StructuredDiagnosticCollectorGroup -GroupId Host -OutputRoot $TestDrive -Format Json
            $result.Status | Should -Be Success
            $result.PSObject.Properties.Name | Should -Not -Contain Command
            $path = Join-Path $TestDrive 'Host\record.json'
            $text = Get-Content -LiteralPath $path -Raw
            $text.TrimStart().StartsWith('[') | Should -BeTrue
            ($text | ConvertFrom-Json).Name | Should -Be 'DVLAB-S1-N01'
            [System.IO.File]::ReadAllBytes($path)[0] | Should -Be 91
            $result.RecordCount | Should -Be 1
            Test-Path -LiteralPath (Join-Path $TestDrive '_Performance') | Should -BeFalse
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

        It 'Preserves performance timestamps and replaces the requested time frame' {
            $script:structuredDiagnosticCollectorCatalog.Groups[0].Collectors = @(@{
                Id = 'Test-Performance'
                Kind = 'Performance'
                RelativePath = 'Host\performance.json'
                Collect = {
                    [PSCustomObject]@{
                        TimeFrame = 'OldValue'
                        Time = [datetime]'2026-01-01T01:00:00Z'
                        Value = 42
                    }
                }
            })
            $from = [datetime]'2026-01-01T00:00:00Z'
            $result = Invoke-StructuredDiagnosticCollectorGroup -GroupId Host -OutputRoot $TestDrive -Format Ndjson `
                -FromDate $from -ToDate $from.AddHours(4)
            $result.Status | Should -Be Success
            $result.RecordCount | Should -Be 1
            $record = Get-Content -LiteralPath (Join-Path $TestDrive 'Host\performance.json') -Raw | ConvertFrom-Json
            $record.TimeFrame | Should -Be LastDay
            [datetime]$record.Time | Should -Be ([datetime]'2026-01-01T01:00:00Z')
            $record.Value | Should -Be 42
            Test-Path -LiteralPath (Join-Path $TestDrive '_Performance') | Should -BeFalse
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

        It 'Passes the requested date range to events' {
            $script:structuredDiagnosticCollectorCatalog.Groups[0].Collectors = @(
                @{ Id = 'Event'; Kind = 'Event'; RelativePath = 'Host\events.json'; LogName = 'DVLAB-Events'; MaximumBytes = 10MB }
            )
            Mock Get-StructuredDiagnosticEvent { [PSCustomObject]@{ Id = 1 } }
            $from = [datetime]'2026-01-01T00:00:00Z'
            $to = $from.AddHours(1)
            $result = Invoke-StructuredDiagnosticCollectorGroup -GroupId Host -OutputRoot $TestDrive -Format Json -IncludeLogs -FromDate $from -ToDate $to
            $result.Status | Should -Be Success
            Should -Invoke Get-StructuredDiagnosticEvent -Times 1 -ParameterFilter {
                $FromDate -eq [datetime]'2026-01-01T00:00:00Z' -and $ToDate -eq [datetime]'2026-01-01T01:00:00Z'
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

        It 'Preserves the artifact records written before a cached collector fails' {
            $script:structuredDiagnosticCollectorCatalog.Groups[0].Collectors[0].Collect = {
                param($context)
                Get-StructuredDiagnosticCachedValue -Cache $context -Key Test -Collect {
                    [PSCustomObject]@{ Name = 'DVLAB' }
                    throw 'Mock collector failure'
                }
            }
            $result = Invoke-StructuredDiagnosticCollectorGroup -GroupId Host -OutputRoot $TestDrive -Format Json -ErrorAction SilentlyContinue
            $result.Status | Should -Be PartialSuccess
            $result.RecordCount | Should -Be 1
            (Get-Content (Join-Path $TestDrive 'Host\record.json') -Raw | ConvertFrom-Json).Name | Should -Be DVLAB
        }

        It 'Reuses inventories within a group but refreshes them for the next group invocation' {
            $script:inventoryCalls = 0
            $collect = {
                param($context)
                Get-StructuredDiagnosticCachedValue -Cache $context -Key VirtualMachines -Collect {
                    $script:inventoryCalls++
                    [PSCustomObject]@{ Name = 'DVLAB-VM01' }
                }
            }
            $group = $script:structuredDiagnosticCollectorCatalog.Groups[0]
            $group.Collectors[0].Collect = $collect
            $group.Collectors += @{ Id = 'Test-Cached'; RelativePath = 'Host\cached.json'; Collect = $collect }

            $first = @(Invoke-StructuredDiagnosticCollectorGroup -GroupId Host -OutputRoot $TestDrive -Format Json)
            $second = @(Invoke-StructuredDiagnosticCollectorGroup -GroupId Host -OutputRoot $TestDrive -Format Json)

            $script:inventoryCalls | Should -Be 2
            $first.Count | Should -Be 2
            $second.Count | Should -Be 2
            @($first + $second | Where-Object { $_.Status -ne 'Success' -or $_.RecordCount -ne 1 }).Count | Should -Be 0
        }

        It 'Continues with the next collector after a command is unavailable' {
            $group = $script:structuredDiagnosticCollectorCatalog.Groups[0]
            $collector = @{
                Id = 'DVLAB-Missing'
                RelativePath = 'Host\missing.json'
                Collect = { Get-DVLABMissingCollectorCommand }
            }
            $group.Collectors = @($collector) + $group.Collectors

            $outputRoot = Join-Path $TestDrive 'missing-command'
            $results = @(Invoke-StructuredDiagnosticCollectorGroup -GroupId Host -OutputRoot $outputRoot -Format Json)
            $results.Count | Should -Be 2
            $results[0].CollectorId | Should -Be 'DVLAB-Missing'
            $results[0].Status | Should -Be CommandNotAvailable
            $results[0].FailureMessage | Should -Match 'Get-DVLABMissingCollectorCommand'
            $results[0].RecordCount | Should -Be 0
            $results[0].OutputArtifacts.Count | Should -Be 0
            Test-Path -LiteralPath (Join-Path $outputRoot $collector.RelativePath) | Should -BeFalse
            $results[1].Status | Should -Be Success
            $results[1].RecordCount | Should -Be 1
            (Get-Content (Join-Path $outputRoot $results[1].RelativePath) -Raw | ConvertFrom-Json).Name | Should -Be 'DVLAB-S1-N01'
            Should -Invoke Trace-Exception -Times 0
        }

        It 'Writes nested manifest artifact metadata without flattening it' {
            Mock Receive-StructuredDiagnosticWorkerGroup {
                [PSCustomObject]@{
                    CollectorId = 'Test-Record'; Status = 'Success'; RecordCount = 1
                    OutputArtifacts = @([PSCustomObject]@{ RelativePath = 'Host\record.json'; Status = 'Success'; RecordCount = 1 })
                }
            }
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
            $manifest.Groups[0].Collectors[0].PSObject.Properties.Name | Should -Not -Contain Command
            $manifest.SchemaVersion | Should -Be 1
            Test-Path -LiteralPath (Join-Path $TestDrive '_Performance') | Should -BeFalse
        }

        It 'Evaluates an unmet group condition only in the worker and reports unavailable results' {
            $script:conditionCalls = 0
            $script:structuredDiagnosticCollectorCatalog.Groups[0].Condition = {
                $script:conditionCalls++
                $false
            }
            Mock Receive-StructuredDiagnosticWorkerGroup {
                Invoke-StructuredDiagnosticCollectorGroup -GroupId Host -OutputRoot $TestDrive -Format Json
            }
            $result = Invoke-StructuredDiagnosticCollection -OutputRoot $TestDrive -CollectionId DVLAB -ModuleVersion '1.0' -Format Json `
                -FromDate (Get-Date).AddHours(-1) -ToDate (Get-Date)
            $result.Status | Should -Be Failed
            $script:conditionCalls | Should -Be 1
            Should -Invoke New-StructuredDiagnosticWorker -Times 1 -Exactly
            Should -Invoke Start-StructuredDiagnosticWorkerGroup -Times 1 -Exactly
            $manifest = Get-Content (Join-Path $TestDrive 'CollectionManifest.json') -Raw | ConvertFrom-Json
            $manifest.Groups[0].Status | Should -Be Unavailable
            $manifest.Groups[0].Collectors[0].PSObject.Properties.Name | Should -Not -Contain Command
        }

        It 'Reports mixed collector outcomes as partial success without discarding repeated statuses' {
            Mock Receive-StructuredDiagnosticWorkerGroup {
                foreach ($status in @('Failed', 'Success', 'Success')) {
                    [PSCustomObject]@{ CollectorId = 'Test-Record'; Status = $status; RecordCount = 1; OutputArtifacts = @() }
                }
            }
            $result = Invoke-StructuredDiagnosticCollection -OutputRoot $TestDrive -CollectionId DVLAB -ModuleVersion '1.0' -Format Json `
                -FromDate (Get-Date).AddHours(-1) -ToDate (Get-Date)
            $manifest = Get-Content (Join-Path $TestDrive 'CollectionManifest.json') -Raw | ConvertFrom-Json
            $result.Status | Should -Be CompletedWithFailures
            $manifest.Groups[0].Status | Should -Be PartialSuccess
            $manifest.Groups[0].Collectors.Count | Should -Be 3
        }

        It 'Retains completed collector results when a group times out' {
            $script:structuredDiagnosticCollectorCatalog.Groups[0].TimeoutSeconds = -1
            $script:structuredDiagnosticCollectorCatalog.Groups[0].Collectors += @{ Id = 'NotFinished'; RelativePath = 'Host\missing.json' }
            Mock New-StructuredDiagnosticWorker {
                @{
                    PowerShell = @{ InvocationStateInfo = @{ State = 'Running' } }
                    Invocation = @{ IsCompleted = $false }
                }
            }
            Mock Receive-StructuredDiagnosticWorkerGroup { [PSCustomObject]@{ CollectorId = 'Test-Record'; Status = 'Success'; RecordCount = 1; OutputArtifacts = @('Host\record.json') } }
            $result = Invoke-StructuredDiagnosticCollection -OutputRoot $TestDrive -CollectionId DVLAB -ModuleVersion '1.0' -Format Json `
                -FromDate (Get-Date).AddHours(-1) -ToDate (Get-Date)
            $manifest = Get-Content (Join-Path $TestDrive 'CollectionManifest.json') -Raw | ConvertFrom-Json
            $result.Status | Should -Be CompletedWithFailures
            $manifest.Groups[0].Status | Should -Be TimedOut
            $manifest.Groups[0].Collectors[0].RecordCount | Should -Be 1
            $manifest.Groups[0].Collectors[1].OutputArtifacts.Count | Should -Be 0
            $manifest.Groups[0].Collectors[1].PSObject.Properties.Name | Should -Not -Contain Command
            Should -Invoke Receive-StructuredDiagnosticWorkerGroup -Times 1 -ParameterFilter { $Stop }
        }

        It 'Reuses two workers across the group queue without standalone scheduling' {
            $script:structuredDiagnosticCollectorCatalog.Groups = @(1..7 | ForEach-Object {
                @{ Id = "DVLAB-Group$_"; TimeoutSeconds = 600; Collectors = @(@{ Id = 'Test-Record' }) }
            })
            Mock Receive-StructuredDiagnosticWorkerGroup {
                [PSCustomObject]@{ CollectorId = 'Test-Record'; Status = 'Success'; RecordCount = 1; OutputArtifacts = @() }
            }

            $result = Invoke-StructuredDiagnosticCollection -OutputRoot $TestDrive -CollectionId DVLAB -ModuleVersion '1.0' -Format Json `
                -FromDate (Get-Date).AddHours(-1) -ToDate (Get-Date)

            $result.Status | Should -Be Completed
            Should -Invoke New-StructuredDiagnosticWorker -Times 2 -Exactly
            Should -Invoke Start-StructuredDiagnosticWorkerGroup -Times 7 -Exactly
            Should -Invoke Remove-StructuredDiagnosticWorker -Times 2 -Exactly
            $manifest = Get-Content (Join-Path $TestDrive 'CollectionManifest.json') -Raw | ConvertFrom-Json
            $manifest.Groups.Count | Should -Be 7
        }

        It 'Replaces a timed-out worker before filling both slots again' {
            $script:structuredDiagnosticCollectorCatalog.Groups = @(1..6 | ForEach-Object {
                @{ Id = "DVLAB-Group$_"; TimeoutSeconds = if ($_ -eq 1) { -1 } else { 600 }; Collectors = @(@{ Id = 'Test-Record' }) }
            })
            $script:structuredDiagnosticCollectorCatalog.Groups[0].Condition = { throw 'Conditions must run inside the worker' }
            $script:workerCount = 0
            Mock New-StructuredDiagnosticWorker {
                $script:workerCount++
                @{
                    PowerShell = @{ InvocationStateInfo = @{ State = if ($script:workerCount -eq 1) { 'Running' } else { 'Completed' } } }
                    Invocation = @{ IsCompleted = $script:workerCount -ne 1 }
                }
            }
            Mock Receive-StructuredDiagnosticWorkerGroup {
                [PSCustomObject]@{ CollectorId = 'Test-Record'; Status = 'Success'; RecordCount = 1; OutputArtifacts = @() }
            }

            $result = Invoke-StructuredDiagnosticCollection -OutputRoot $TestDrive -CollectionId DVLAB -ModuleVersion '1.0' -Format Json `
                -FromDate (Get-Date).AddHours(-1) -ToDate (Get-Date)

            $result.Status | Should -Be CompletedWithFailures
            Should -Invoke New-StructuredDiagnosticWorker -Times 3 -Exactly
            Should -Invoke Receive-StructuredDiagnosticWorkerGroup -Times 1 -Exactly -ParameterFilter { $Stop }
            Should -Invoke Remove-StructuredDiagnosticWorker -Times 3 -Exactly
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

        It 'Deduplicates explicit targets case-insensitively while preserving first spelling and order' {
            $targets = @(Get-StructuredDiagnosticTarget -ComputerName dvlab-s1-n02,DVLAB-S1-N01,DVLAB-S1-N02,dvlab-s1-n01)
            $targets.Count | Should -Be 2
            ($targets -join ',') | Should -BeExactly 'dvlab-s1-n02,DVLAB-S1-N01'
            Should -Invoke Trace-Output -Times 2 -Exactly -ParameterFilter { $Level -eq 'Warning' }
            Should -Invoke Test-Path -Times 0 -ParameterFilter { $LiteralPath -eq 'HKLM:\Cluster' }
            Should -Invoke Get-ClusterNode -Times 0
        }

        It 'Warns and skips a duplicate FQDN alias' {
            $targets = @(Get-StructuredDiagnosticTarget -ComputerName 'DVLAB-S1-N01', 'dvlab-s1-n01.dvlab.contoso.local')
            $targets.Count | Should -Be 1
            $targets[0] | Should -BeExactly 'DVLAB-S1-N01'
            Should -Invoke Trace-Output -Times 1 -Exactly -ParameterFilter { $Level -eq 'Warning' }
            Should -Invoke Get-ClusterNode -Times 0
        }

        It 'Resolves every configured cluster node including unavailable nodes' {
            $targets = @(Get-StructuredDiagnosticTarget)
            $targets | Should -Be @('DVLAB-S1-N01', 'DVLAB-S1-N02', 'DVLAB-S1-N03')
            Should -Invoke Get-ClusterNode -Times 1
        }

        It 'Surfaces failed cluster enumeration without falling back to localhost' {
            Mock Get-ClusterNode { throw 'DVLAB cluster unavailable' }
            { Get-StructuredDiagnosticTarget -ErrorAction Stop } | Should -Throw '*DVLAB cluster unavailable*'
            Should -Invoke Trace-Exception -Times 1
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
            Mock Remove-Job -RemoveParameterType Job {}
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
            Should -Invoke Remove-Job -Times 1 -Exactly -ParameterFilter {
                $Job.Name -eq 'SdnDiag-Local-DVLAB' -and $Force
            }
            Should -Invoke Copy-FileFromRemoteComputer -Times 0
            Should -Invoke Clear-SdnWorkingDirectory -Times 0
        }

        It 'Starts both collection jobs before waiting and reports group progress' {
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
                $progressJobs = @([PSCustomObject]@{
                    Output = @([PSCustomObject]@{
                        StructuredDiagnosticProgressEvent = $true; EventId = 'remote-host'
                        Node = 'DVLAB-S1-N02'; PSComputerName = 'DVLAB-S1-N02'; GroupId = 'Host'
                        Status = 'Success'; CompletedCount = 1; TotalCount = 17
                        RemainingGroups = @('Cluster', 'HyperV')
                    })
                    ChildJobs = @([PSCustomObject]@{
                        State = 'Running'; Location = 'DVLAB-S1-N02'; Output = @()
                    })
                })
                & $ProgressUpdateScript $progressJobs @{}
                & $script:remoteScriptBlock @script:remoteArgumentList
                & $script:localScriptBlock @script:localArgumentList
            }

            $result = Invoke-StructuredDiagnostics -ComputerName DVLAB-S1-N01,DVLAB-S1-N02 `
                -OutputDirectory $script:collectionOutput

            $result.Status | Should -Be Completed
            ($script:startOrder -join ',') | Should -Be 'RemoteJob,LocalJob,Wait'
            Should -Invoke Trace-Output -Times 1 -ParameterFilter {
                $ComputerName -eq 'DVLAB-S1-N02' -and
                $Message -like 'Completed structured diagnostics group Host *'
            }
            Should -Invoke Remove-Job -Times 2 -Exactly -ParameterFilter {
                $Job.Name -in @('SdnDiag-DVLAB', 'SdnDiag-Local-DVLAB') -and $Force
            }
        }

        It 'Removes both owned collection jobs when waiting for results fails' {
            Mock Test-ComputerNameIsLocal { $ComputerName -eq 'DVLAB-S1-N01' }
            Mock Wait-PSJob { throw 'DVLAB wait failed' }

            { Invoke-StructuredDiagnostics -ComputerName DVLAB-S1-N01,DVLAB-S1-N02 `
                -OutputDirectory $script:collectionOutput -ErrorAction Stop } | Should -Throw '*DVLAB wait failed*'

            Should -Invoke Remove-Job -Times 2 -Exactly
            Should -Invoke Remove-Job -Times 1 -Exactly -ParameterFilter {
                $Job.Name -eq 'SdnDiag-DVLAB' -and $Force
            }
            Should -Invoke Remove-Job -Times 1 -Exactly -ParameterFilter {
                $Job.Name -eq 'SdnDiag-Local-DVLAB' -and $Force
            }
        }

        It 'Reports a job cleanup failure and still removes the remaining owned job' {
            Mock Test-ComputerNameIsLocal { $ComputerName -eq 'DVLAB-S1-N01' }
            Mock Remove-Job -RemoveParameterType Job {
                if ($Job.Name -eq 'SdnDiag-DVLAB') {
                    throw 'DVLAB job cleanup failed'
                }
            }
            Mock Write-Error {}

            $result = Invoke-StructuredDiagnostics -ComputerName DVLAB-S1-N01,DVLAB-S1-N02 `
                -OutputDirectory $script:collectionOutput

            $result.Status | Should -Be Completed
            Should -Invoke Remove-Job -Times 2 -Exactly
            Should -Invoke Remove-Job -Times 1 -Exactly -ParameterFilter {
                $Job.Name -eq 'SdnDiag-Local-DVLAB' -and $Force
            }
            Should -Invoke Trace-Exception -Times 1 -Exactly
            Should -Invoke Write-Error -Times 1 -Exactly
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
            $credential = [pscredential]::new('DVLAB\operator', [securestring]::new())
            $result = Invoke-StructuredDiagnostics -ComputerName DVLAB-S1-N01 `
                -OutputDirectory $script:collectionOutput -Credential $credential
            $result.Status | Should -Be Completed
            Should -Invoke Invoke-PSRemoteCommand -Times 1 -ParameterFilter {
                $Credential.UserName -eq 'DVLAB\operator' -and $ImportModuleOnRemoteSession -and $AsJob -and -not $PassThru
            }
            Should -Invoke Wait-PSJob -Times 1 -ParameterFilter {
                $Name -contains 'SdnDiag-DVLAB' -and $Activity -eq 'Structured diagnostics' -and
                    $ExecutionTimeOut -eq 1800 -and
                    $null -ne $ProgressStatusScript -and $null -ne $ProgressPercentScript -and
                    $null -ne $ProgressUpdateScript -and $ShowProgress
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
            Should -Invoke Remove-Job -Times 1 -Exactly -ParameterFilter {
                $Job.Name -eq 'SdnDiag-DVLAB' -and $Force
            }
        }

        It 'Cleans staging when remote copy fails' {
            Mock Test-ComputerNameIsLocal { $false }
            Mock Copy-FileFromRemoteComputer { throw 'DVLAB copy failed' }
            { Invoke-StructuredDiagnostics -ComputerName DVLAB-S1-N01 -OutputDirectory $script:collectionOutput -ErrorAction Stop } |
                Should -Throw '*every requested computer*'
            Should -Invoke Clear-SdnWorkingDirectory -Times 1 -Exactly -ParameterFilter {
                $ComputerName -contains 'DVLAB-S1-N01' -and
                $Path -contains (Join-Path $TestDrive "StructuredDiagnostics_Staging\$script:collectionId")
            }
            $manifest = Get-Content (Join-Path $script:collectionOutput 'StructuredDiagnostics\ClusterCollectionManifest.json') -Raw |
                ConvertFrom-Json
            $manifest.Status | Should -Be Failed
            $manifest.Nodes[0].FailureMessage | Should -Match 'copy failed'
        }

        It 'Rejects invalid dates and unsafe or colliding directory names before contacting nodes' {
            { Invoke-StructuredDiagnostics -FromDate ([datetime]'2026-01-02') -ToDate ([datetime]'2026-01-01') } | Should -Throw '*FromDate*'
            { Invoke-StructuredDiagnostics -ComputerName '..' -OutputDirectory $script:collectionOutput } | Should -Throw '*directory name*'
            { Invoke-StructuredDiagnostics -ComputerName 'DVLAB:One','DVLAB?One' -OutputDirectory $script:collectionOutput } | Should -Throw '*directory name*'
            Should -Invoke Invoke-PSRemoteCommand -Times 0
            Should -Invoke Initialize-DataCollection -Times 0
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
            Should -Invoke Remove-Job -Times 0
        }
    }
}
