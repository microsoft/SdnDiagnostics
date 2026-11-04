# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Import-Module -Name $PSScriptRoot\SdnDiag.Utilities.psm1 -ErrorAction Stop

. (Join-Path $PSScriptRoot 'SdnDiag.StructuredDiagnostics.CollectorCatalog.ps1')

# Runs collector groups concurrently, enforces group deadlines, and writes the collection manifest.
function Invoke-StructuredDiagnosticCollection {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$OutputRoot,

        [Parameter(Mandatory = $true)]
        [string]$CollectionId,

        [Parameter(Mandatory = $true)]
        [string]$ModuleVersion,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Json', 'Ndjson')]
        [string]$Format,

        [Parameter(Mandatory = $true)]
        [DateTime]$FromDate,

        [Parameter(Mandatory = $true)]
        [DateTime]$ToDate,

        [Parameter()]
        [switch]$IncludeLogs,

        [Parameter()]
        [switch]$EmitProgressEvents
    )

    if ($FromDate -gt $ToDate) {
        throw 'FromDate must be earlier than or equal to ToDate.'
    }

    $started = [DateTime]::UtcNow
    $pending = [System.Collections.ArrayList]::new()
    $groupManifestResults = [System.Collections.ArrayList]::new()
    $progressInterval = [TimeSpan]::FromSeconds(30)
    $nextProgressUpdate = [DateTime]::UtcNow.Add($progressInterval)
    $nodeResult = [PSCustomObject]@{
        Node = $env:COMPUTERNAME
        Status = 'Failed'
        ManifestPath = 'CollectionManifest.json'
        FailureMessage = $null
    }
    $writer = $null
    try {
        $null = New-Item -Path $OutputRoot -ItemType Directory -Force -ErrorAction Stop
        foreach ($group in $script:structuredDiagnosticCollectorCatalog.Groups) {
            $groupStart = [DateTime]::UtcNow
            $job = $null
            $failureMessage = $null
            $status = 'Failed'
            try {
                $conditionMet = -not $group.Condition -or (& $group.Condition)
                if ($conditionMet) {
                    $job = Start-Job -ScriptBlock {
                        param($groupId, $outputRoot, $format, $modulePath, $fromDate, $toDate, $includeLogs)
                        Import-Module $modulePath -ErrorAction Stop
                        Invoke-StructuredDiagnosticCollectorGroup -GroupId $groupId -OutputRoot $outputRoot -Format $format `
                            -FromDate $fromDate -ToDate $toDate -IncludeLogs:$includeLogs
                    } -ArgumentList $group.Id, $OutputRoot, $Format, $PSCommandPath, $FromDate, $ToDate, $IncludeLogs.IsPresent -ErrorAction Stop
                }
                else {
                    $status = 'Unavailable'
                    $failureMessage = 'Group condition was not met on this host.'
                }
            }
            catch {
                $failureMessage = $_.Exception.Message
                $_ | Trace-Exception
                $_ | Write-Error -ErrorAction Continue
            }
            [void]$pending.Add(@{
                Group = $group
                Job = $job
                Started = $groupStart
                Deadline = $groupStart.AddSeconds($group.TimeoutSeconds)
                FailureMessage = $failureMessage
                Status = $status
            })
        }

        $groupCount = $pending.Count
        Trace-Output -Level:Verbose -Message (
            "Started {0} structured diagnostic collector group(s) on '{1}'." -f
            $groupCount, $nodeResult.Node
        )
        if ($EmitProgressEvents) {
            [PSCustomObject]@{
                StructuredDiagnosticProgressEvent = $true
                EventId = [guid]::NewGuid().ToString('N')
                Node = $nodeResult.Node
                GroupId = $null
                Status = 'Running'
                CompletedCount = 0
                TotalCount = $groupCount
                RemainingGroups = @($pending | ForEach-Object { $_.Group.Id })
                DurationSeconds = 0
            }
        }

        # All jobs start before waiting. Check every deadline, not just the first group's.
        while ($pending.Count -gt 0) {
            foreach ($entry in @($pending.ToArray())) {
                $status = $entry.Status
                $receivedResults = @()
                $jobCompleted = $false
                if ($entry.Job) {
                    if ($entry.Job.State -in @('Completed', 'Failed', 'Stopped')) {
                        $receivedResults = @(Receive-Job -Job $entry.Job -ErrorAction Continue)
                        $jobCompleted = $entry.Job.State -eq 'Completed'
                        if (-not $jobCompleted) {
                            $entry.FailureMessage = 'Group job ended without a collector result: {0}.' -f $entry.Job.State
                        }
                    }
                    elseif ($entry.Job.State -eq 'Blocked') {
                        Stop-Job -Job $entry.Job
                        $receivedResults = @(Receive-Job -Job $entry.Job -ErrorAction Continue)
                        $entry.FailureMessage = 'Group job was blocked waiting for user interaction.'
                    }
                    elseif ([DateTime]::UtcNow -ge $entry.Deadline) {
                        Stop-Job -Job $entry.Job
                        $receivedResults = @(Receive-Job -Job $entry.Job -ErrorAction Continue)
                        $status = 'TimedOut'
                        $entry.FailureMessage = 'Group exceeded its timeout of {0} seconds.' -f $entry.Group.TimeoutSeconds
                    }
                    else {
                        continue
                    }
                    Remove-Job -Job $entry.Job -Force
                }
                $collectorResults = [System.Collections.ArrayList]::new()
                $reportedResults = @($receivedResults | Where-Object { $_.PSObject.Properties.Name -contains 'CollectorId' })
                if ($jobCompleted -and $reportedResults.Count -gt 0) {
                    foreach ($result in $reportedResults) {
                        [void]$collectorResults.Add(($result | Select-Object CollectorId, Command, Status, RelativePath, RecordCount, DurationSeconds, FailureMessage, OutputArtifacts, Truncated))
                    }
                }
                else {
                    foreach ($collector in $entry.Group.Collectors) {
                        $result = $reportedResults | Where-Object { $_.CollectorId -eq $collector.Id } | Select-Object -First 1
                        if (-not $result) {
                            $result = [PSCustomObject]@{
                                CollectorId = $collector.Id
                                Command = $collector.CommandName
                                Status = $status
                                RelativePath = $collector.RelativePath
                                RecordCount = 0
                                DurationSeconds = ([DateTime]::UtcNow - $entry.Started).TotalSeconds
                                FailureMessage = $entry.FailureMessage
                                OutputArtifacts = @()
                                Truncated = $false
                            }
                        }
                        [void]$collectorResults.Add(($result | Select-Object CollectorId, Command, Status, RelativePath, RecordCount, DurationSeconds, FailureMessage, OutputArtifacts, Truncated))
                    }
                }

                $groupStatus = $status
                if ($jobCompleted -and $reportedResults.Count -gt 0) {
                    $collectorStatuses = @($collectorResults.Status | Select-Object -Unique)
                    # Roll collector outcomes up while preserving partial success when any data was captured.
                    if ($collectorStatuses -contains 'Failed') {
                        $groupStatus = 'Failed'
                        if ($collectorStatuses -contains 'Success' -or $collectorStatuses -contains 'PartialSuccess') {
                            $groupStatus = 'PartialSuccess'
                        }
                    }
                    elseif ($collectorStatuses -contains 'PartialSuccess') {
                        $groupStatus = 'PartialSuccess'
                    }
                    elseif ($collectorStatuses -contains 'Success') {
                        $groupStatus = 'Success'
                    }
                    else {
                        $groupStatus = 'Unavailable'
                    }
                }
                $groupResult = [PSCustomObject]@{
                    GroupId = $entry.Group.Id
                    Status = $groupStatus
                    DurationSeconds = ([DateTime]::UtcNow - $entry.Started).TotalSeconds
                    Collectors = @($collectorResults.ToArray())
                }
                [void]$groupManifestResults.Add($groupResult)
                Trace-Output -Level:Verbose -Message (
                    ("Structured diagnostic collector group '{0}' on '{1}' finished with status '{2}' " +
                    "({3}/{4} groups complete, {5:N1} seconds).") -f
                    $groupResult.GroupId, $nodeResult.Node, $groupResult.Status,
                    $groupManifestResults.Count, $groupCount, $groupResult.DurationSeconds
                )
                if ($EmitProgressEvents) {
                    $remainingGroups = @($pending | Where-Object { $_ -ne $entry } | ForEach-Object { $_.Group.Id })
                    [PSCustomObject]@{
                        StructuredDiagnosticProgressEvent = $true
                        EventId = [guid]::NewGuid().ToString('N')
                        Node = $nodeResult.Node
                        GroupId = $groupResult.GroupId
                        Status = $groupResult.Status
                        CompletedCount = $groupManifestResults.Count
                        TotalCount = $groupCount
                        RemainingGroups = $remainingGroups
                        DurationSeconds = $groupResult.DurationSeconds
                    }
                }
                $pending.Remove($entry)
            }
            if ($pending.Count -gt 0) {
                if ([DateTime]::UtcNow -ge $nextProgressUpdate) {
                    $pendingGroupIds = @($pending | ForEach-Object { $_.Group.Id })
                    Trace-Output -Level:Verbose -Message (
                        "Structured diagnostic collection is still running on '{0}' ({1}/{2} groups complete). Pending: {3}." -f
                        $nodeResult.Node, $groupManifestResults.Count, $groupCount, ($pendingGroupIds -join ', ')
                    )
                    $nextProgressUpdate = [DateTime]::UtcNow.Add($progressInterval)
                }
                $null = Wait-Job -Job @($pending | ForEach-Object { $_.Job }) -Any -Timeout 1
            }
        }

        $nodeResult.Status = 'Completed'
        if (@($groupManifestResults | Where-Object { $_.Status -in @('Failed', 'PartialSuccess', 'TimedOut') }).Count -gt 0) {
            $nodeResult.Status = 'CompletedWithFailures'
        }
        if (@($groupManifestResults.Collectors | Where-Object { $_.Status -in @('Success', 'PartialSuccess') }).Count -eq 0) {
            $nodeResult.Status = 'Failed'
            $nodeResult.FailureMessage = 'No collector produced a usable result.'
        }
        $manifest = [PSCustomObject]@{
            SchemaVersion = 1
            CollectionId = $CollectionId
            Node = $nodeResult.Node
            ModuleVersion = $ModuleVersion
            Format = $Format
            IncludeLogs = $IncludeLogs.IsPresent
            FromDateUtc = $FromDate.ToUniversalTime().ToString('o')
            ToDateUtc = $ToDate.ToUniversalTime().ToString('o')
            PerformanceTimeFrame = Get-StructuredDiagnosticPerformanceTimeFrame -FromDate $FromDate -ToDate $ToDate
            StartedUtc = $started.ToString('o')
            CompletedUtc = [DateTime]::UtcNow.ToString('o')
            Status = $nodeResult.Status
            Groups = @($groupManifestResults.ToArray())
        }
        $writer = Open-StructuredDiagnosticArtifactWriter -Path (Join-Path $OutputRoot 'CollectionManifest.json') -Format 'Text'
        $writer.Stream.Write(($manifest | ConvertTo-Json -Depth 20 -ErrorAction Stop))
        Close-StructuredDiagnosticArtifactWriter -Writer $writer
        Trace-Output -Level:Verbose -Message (
            "Structured diagnostic collection on '{0}' completed with status '{1}'." -f
            $nodeResult.Node, $nodeResult.Status
        )
    }
    catch {
        $nodeResult.Status = 'Failed'
        $nodeResult.FailureMessage = $_.Exception.Message
        $_ | Trace-Exception
        $_ | Write-Error -ErrorAction Continue
    }
    finally {
        foreach ($entry in $pending) {
            if ($entry.Job) {
                Stop-Job -Job $entry.Job
                Remove-Job -Job $entry.Job -Force
            }
        }
        if ($writer) {
            $writer.Stream.Dispose()
            if (Test-Path -LiteralPath $writer.TemporaryPath) {
                Remove-Item -LiteralPath $writer.TemporaryPath -Force
            }
        }
    }
    return $nodeResult
}

# Runs every collector in a catalog group and returns a status record for each collector.
function Invoke-StructuredDiagnosticCollectorGroup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Host', 'NetAdapter', 'VM', 'Lbfo', 'TcpIp', 'Dns', 'Nat', 'HyperV', 'Cluster', 'ClusterPerf', 'VMSwitch', 'VMNetworkAdapter', 'Qos', 'Lldp', 'Smb', 'NetworkATC', 'Proxy', 'Firewall')]
        [string]$GroupId,

        [Parameter(Mandatory = $true)]
        [string]$OutputRoot,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Json', 'Ndjson')]
        [string]$Format,

        [Parameter()]
        [DateTime]$FromDate = (Get-Date).AddHours(-4),

        [Parameter()]
        [DateTime]$ToDate = (Get-Date),

        [Parameter()]
        [switch]$IncludeLogs
    )

    $group = $script:structuredDiagnosticCollectorCatalog.Groups | Where-Object { $_.Id -eq $GroupId }
    if ($group.Condition -and -not (& $group.Condition)) {
        foreach ($collector in $group.Collectors) {
            [PSCustomObject]@{
                GroupId = $group.Id
                CollectorId = $collector.Id
                Command = $collector.CommandName
                Status = 'Unavailable'
                RelativePath = $collector.RelativePath
                RecordCount = 0
                DurationSeconds = 0
                FailureMessage = 'Group condition was not met on this host.'
                OutputArtifacts = @()
                Truncated = $false
            }
        }
        return
    }

    foreach ($collector in $group.Collectors) {
        $started = [DateTime]::UtcNow
        $writer = $null
        $result = [PSCustomObject]@{
            GroupId = $group.Id
            CollectorId = $collector.Id
            Command = $collector.CommandName
            Status = 'Success'
            RelativePath = $collector.RelativePath
            RecordCount = 0
            DurationSeconds = 0
            FailureMessage = $null
            OutputArtifacts = @()
            Truncated = $false
        }
        try {
            if (($collector.Kind -eq 'Event' -or $collector.RequiresLogs) -and -not $IncludeLogs) {
                $result.Status = 'Skipped'
                $result.FailureMessage = 'IncludeLogs was not requested.'
            }
            elseif ($collector.CommandName -and -not (Get-Command -Name $collector.CommandName -ErrorAction Ignore 4>$null)) {
                $result.Status = 'Unavailable'
                $result.FailureMessage = 'Command {0} is unavailable.' -f $collector.CommandName
            }
            elseif ($collector.TestAvailable -and -not (& $collector.TestAvailable)) {
                $result.Status = 'Unavailable'
                $result.FailureMessage = 'Collector {0} is not applicable on this host.' -f $collector.Id
            }
            elseif ($collector.Kind -eq 'FileSet') {
                $artifacts = @(& $collector.Collect $OutputRoot $Format)
                $result.OutputArtifacts = $artifacts
                $result.RecordCount = @($artifacts | Where-Object Status -eq 'Success').Count
                $result.Truncated = @($artifacts | Where-Object Truncated).Count -gt 0
                $failures = @($artifacts | Where-Object Status -eq 'Failed')
                # Reduce per-file outcomes into the collector-level manifest status.
                if ($result.RecordCount -eq 0) {
                    $result.Status = 'Unavailable'
                    if ($failures.Count -gt 0) { $result.Status = 'Failed' }
                }
                elseif ($failures.Count -gt 0 -or $result.Truncated) {
                    $result.Status = 'PartialSuccess'
                }
                $result.FailureMessage = ($failures.FailureMessage -join '; ')
            }
            else {
                $artifactFormat = $Format
                if ($collector.Kind -eq 'Text') {
                    $artifactFormat = 'Text'
                }
                elseif ($collector.Kind -eq 'Event') {
                    $artifactFormat = 'Ndjson'
                }
                $writer = Open-StructuredDiagnosticArtifactWriter -Path (Join-Path $OutputRoot $collector.RelativePath) `
                    -Format $artifactFormat -MaximumBytes $collector.MaximumBytes
                try {
                    if ($collector.Kind -eq 'Event') {
                        Get-StructuredDiagnosticEvent -LogName $collector.LogName -FromDate $FromDate -ToDate $ToDate | ForEach-Object {
                                Write-StructuredDiagnosticArtifactRecord -Writer $writer -Record $_
                            }
                    }
                    elseif ($collector.Kind -eq 'Performance') {
                        $timeFrame = Get-StructuredDiagnosticPerformanceTimeFrame -FromDate $FromDate -ToDate $ToDate
                        & $collector.Collect $timeFrame | ForEach-Object {
                            $performanceRecord = ConvertTo-StructuredDiagnosticRecord -InputObject $_ `
                                -ExcludedProperties $collector.ExcludedProperties -FormatDateTime
                            $performanceRecord | Add-Member -NotePropertyName TimeFrame -NotePropertyValue $timeFrame -Force
                            Write-StructuredDiagnosticArtifactRecord -Writer $writer -Record $performanceRecord
                        }
                    }
                    else {
                        & $collector.Collect | ForEach-Object {
                            Write-StructuredDiagnosticArtifactRecord -Writer $writer -Record $_ -ExcludedProperties $collector.ExcludedProperties
                        }
                    }
                }
                catch {
                    if ($_.Exception.Message -eq 'StructuredDiagnosticArtifactSizeLimitReached') {
                        $result.Truncated = $true
                        $result.Status = 'PartialSuccess'
                        $result.FailureMessage = 'Artifact reached its maximum size of {0} bytes.' -f $collector.MaximumBytes
                    }
                    else {
                        $result.FailureMessage = $_.Exception.Message
                    }
                    $eventUnavailable = $collector.Kind -eq 'Event' -and $writer.RecordCount -eq 0 -and
                        $_.Exception.Message -match 'cannot find|does not exist|not an event log|disabled|No events were found'
                    $expectedUnavailable = $writer.RecordCount -eq 0 -and $collector.ExpectedUnavailableFailure -and
                        $_.Exception.Message -match $collector.ExpectedUnavailableFailure
                    # Expected platform gaps are unavailable; failures after output began are partial successes.
                    if ($eventUnavailable -or $expectedUnavailable) {
                        $result.Status = 'Unavailable'
                    }
                    elseif (-not $result.Truncated) {
                        $result.Status = 'Failed'
                        if ($writer.RecordCount -gt 0) {
                            $result.Status = 'PartialSuccess'
                        }
                        $_ | Trace-Exception
                        Write-Error -Message ('[{0}/{1}] Collector failed: {2}' -f $group.Id, $collector.Id, $_.Exception.Message) -ErrorAction Continue
                    }
                }
                Close-StructuredDiagnosticArtifactWriter -Writer $writer
                $result.RecordCount = $writer.RecordCount
                $result.OutputArtifacts = @($collector.RelativePath)
            }
        }
        catch {
            $result.Status = 'Failed'
            $result.FailureMessage = $_.Exception.Message
            $_ | Trace-Exception
            Write-Error -Message ('[{0}/{1}] {2}' -f $group.Id, $collector.Id, $_.Exception.Message) -ErrorAction Continue
        }
        finally {
            if ($writer) {
                $writer.Stream.Dispose()
                if (Test-Path -LiteralPath $writer.TemporaryPath) {
                    Remove-Item -LiteralPath $writer.TemporaryPath -Force
                }
            }
        }
        $result.DurationSeconds = ([DateTime]::UtcNow - $started).TotalSeconds
        $result
    }
}

# ===========================
#     Collection Helper Functions
# ===========================

# Recursively converts PowerShell and CIM objects into JSON-safe records with bounded depth.
function ConvertTo-StructuredDiagnosticRecord {
    [CmdletBinding()]
    param (
        [Parameter()]
        [AllowNull()]
        $InputObject,

        [Parameter()]
        [int]$Depth = 0,

        [Parameter()]
        [string[]]$ExcludedProperties = @(),

        [Parameter()]
        [switch]$FormatDateTime
    )

    if ($FormatDateTime -and ($InputObject -is [DateTime] -or $InputObject -is [DateTimeOffset])) {
        return $InputObject.ToString('o')
    }

    if ($null -eq $InputObject -or $InputObject -is [string] -or $InputObject -is [ValueType]) {
        return $InputObject
    }

    # Bound traversal to the JSON depth, including cyclic Hyper-V object references.
    if ($Depth -gt 5) {
        return [string]$InputObject
    }

    $excluded = @('CimClass', 'CimInstanceProperties', 'CimSystemProperties', 'CimSession') + $ExcludedProperties
    $record = [ordered]@{}
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ($key -notin $excluded) {
                $record[$key] = ConvertTo-StructuredDiagnosticRecord -InputObject $InputObject[$key] -Depth ($Depth + 1) -ExcludedProperties $ExcludedProperties -FormatDateTime:$FormatDateTime
            }
        }
    }
    elseif ($InputObject -is [System.Collections.IEnumerable]) {
        $items = @(foreach ($item in $InputObject) {
            ConvertTo-StructuredDiagnosticRecord -InputObject $item -Depth ($Depth + 1) -ExcludedProperties $ExcludedProperties -FormatDateTime:$FormatDateTime
        })
        return ,$items
    }
    else {
        foreach ($property in $InputObject.PSObject.Properties) {
            if ($property.IsGettable -and $property.Name -notin $excluded) {
                $record[$property.Name] = ConvertTo-StructuredDiagnosticRecord -InputObject $property.Value -Depth ($Depth + 1) -ExcludedProperties $ExcludedProperties -FormatDateTime:$FormatDateTime
            }
        }
    }
    return [PSCustomObject]$record
}

# Creates a temporary streaming writer for JSON, NDJSON, or text diagnostic artifacts.
function Open-StructuredDiagnosticArtifactWriter {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Json', 'Ndjson', 'Text')]
        [string]$Format,

        [Parameter()]
        [long]$MaximumBytes = 0
    )

    $directory = Split-Path -Path $Path -Parent
    if (-not (Test-Path -LiteralPath $directory)) {
        $null = New-Item -Path $directory -ItemType Directory -Force -ErrorAction Stop
    }
    $temporaryPath = '{0}.{1}.tmp' -f $Path, [guid]::NewGuid().ToString('N')
    $stream = [System.IO.StreamWriter]::new($temporaryPath, $false, [System.Text.UTF8Encoding]::new($false))
    if ($Format -eq 'Json') {
        $stream.WriteLine('[')
    }
    return [PSCustomObject]@{
        Path = $Path
        TemporaryPath = $temporaryPath
        Format = $Format
        Stream = $stream
        RecordCount = 0
        MaximumBytes = $MaximumBytes
        BytesWritten = if ($Format -eq 'Json') { 2L } else { 0L }
        Truncated = $false
    }
}

# Serializes one record to an artifact writer while enforcing any configured size limit.
function Write-StructuredDiagnosticArtifactRecord {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $Writer,

        [Parameter(Mandatory = $true)]
        $Record,

        [Parameter()]
        [string[]]$ExcludedProperties = @()
    )

    if ($Writer.Format -eq 'Text') {
        $line = [string]$Record
        $recordBytes = [System.Text.Encoding]::UTF8.GetByteCount($line + [Environment]::NewLine)
        if ($Writer.MaximumBytes -gt 0 -and ($Writer.BytesWritten + $recordBytes) -gt $Writer.MaximumBytes) {
            $Writer.Truncated = $true
            throw 'StructuredDiagnosticArtifactSizeLimitReached'
        }
        $Writer.Stream.WriteLine($line)
        $Writer.BytesWritten += $recordBytes
        $Writer.RecordCount++
        return
    }

    $plainRecord = ConvertTo-StructuredDiagnosticRecord -InputObject $Record -ExcludedProperties $ExcludedProperties
    $json = ConvertTo-Json -InputObject $plainRecord -Depth 5 -Compress:($Writer.Format -eq 'Ndjson') -ErrorAction Stop
    if ($Writer.Format -eq 'Json') {
        if ($Writer.RecordCount -gt 0) {
            $Writer.Stream.WriteLine(',')
        }
        $Writer.Stream.Write($json)
    }
    else {
        $recordBytes = [System.Text.Encoding]::UTF8.GetByteCount($json + [Environment]::NewLine)
        if ($Writer.MaximumBytes -gt 0 -and ($Writer.BytesWritten + $recordBytes) -gt $Writer.MaximumBytes) {
            $Writer.Truncated = $true
            throw 'StructuredDiagnosticArtifactSizeLimitReached'
        }
        $Writer.Stream.WriteLine($json)
        $Writer.BytesWritten += $recordBytes
    }
    $Writer.RecordCount++
}

# Reads an enabled Windows event log and emits normalized event records for the requested period.
function Get-StructuredDiagnosticEvent {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$LogName,

        [Parameter()]
        [DateTime]$FromDate,

        [Parameter()]
        [DateTime]$ToDate,

        [Parameter()]
        [switch]$AllEvents
    )

    $log = Get-WinEvent -ListLog $LogName -ErrorAction Stop
    if (-not $log.IsEnabled) {
        throw "Event log '$LogName' is disabled."
    }

    $filter = @{ LogName = $LogName }
    if (-not $AllEvents) {
        $filter.StartTime = $FromDate
        $filter.EndTime = $ToDate
    }

    try {
        Get-WinEvent -FilterHashtable $filter -ErrorAction Stop | Select-Object -Property ProviderName, Id, Level,
            LevelDisplayName, @{ Name = 'TimeCreated'; Expression = { ([DateTimeOffset]$_.TimeCreated).UtcDateTime.ToString('o') } },
            RecordId, LogName, MachineName, UserId, ProcessId, ThreadId, Task,
            TaskDisplayName, Opcode, OpcodeDisplayName, Keywords, KeywordsDisplayNames, Message
    }
    catch {
        if ($_.Exception.Message -notmatch 'No events were found') {
            throw
        }
    }
}

# Finalizes an artifact stream and atomically moves the temporary file into place.
function Close-StructuredDiagnosticArtifactWriter {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $Writer
    )

    try {
        if ($Writer.Format -eq 'Json') {
            $Writer.Stream.WriteLine()
            $Writer.Stream.WriteLine(']')
        }
        $Writer.Stream.Dispose()
        Move-Item -LiteralPath $Writer.TemporaryPath -Destination $Writer.Path -Force -ErrorAction Stop
    }
    finally {
        $Writer.Stream.Dispose()
    }
}
