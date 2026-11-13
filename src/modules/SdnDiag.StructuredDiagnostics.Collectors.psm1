# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Import-Module -Name $PSScriptRoot\SdnDiag.Utilities.psm1 -ErrorAction Stop

. (Join-Path $PSScriptRoot 'SdnDiag.StructuredDiagnostics.CollectorCatalog.ps1')

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
    $queued = [System.Collections.Queue]::new()
    foreach ($group in $script:structuredDiagnosticCollectorCatalog.Groups) {
        $queued.Enqueue($group)
    }
    $workers = [System.Collections.ArrayList]::new()
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
        $groupCount = $queued.Count
        Trace-Output -Level:Verbose -Message (
            "Queued {0} structured diagnostic collector group(s) on '{1}'." -f
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
                RemainingGroups = @($queued.ToArray() | ForEach-Object { $_.Id })
                RunningGroups = @()
                QueuedGroups = @($queued.ToArray() | ForEach-Object { $_.Id })
                DurationSeconds = 0
            }
        }

        while ($queued.Count -gt 0 -or $pending.Count -gt 0) {
            $startedGroups = $false
            while ($queued.Count -gt 0 -and $pending.Count -lt 2) {
                $group = $queued.Dequeue()
                $groupStart = [DateTime]::UtcNow
                $worker = $null
                $failureMessage = $null
                $status = 'Failed'
                try {
                    $worker = $workers | Where-Object { $pending.Worker -notcontains $_ } | Select-Object -First 1
                    if (-not $worker) {
                        $worker = New-StructuredDiagnosticWorker
                        [void]$workers.Add($worker)
                    }
                    Start-StructuredDiagnosticWorkerGroup -Worker $worker -GroupId $group.Id -OutputRoot $OutputRoot `
                        -Format $Format -ModulePath $PSCommandPath -FromDate $FromDate -ToDate $ToDate -IncludeLogs:$IncludeLogs
                }
                catch {
                    $failureMessage = $_.Exception.Message
                    $_ | Trace-Exception
                    $_ | Write-Error -ErrorAction Continue
                    if ($worker) {
                        Remove-StructuredDiagnosticWorker -Worker $worker
                        $workers.Remove($worker)
                        $worker = $null
                    }
                }
                [void]$pending.Add(@{
                    Group = $group
                    Worker = $worker
                    Started = $groupStart
                    Deadline = $groupStart.AddSeconds($group.TimeoutSeconds)
                    FailureMessage = $failureMessage
                    Status = $status
                })
                $startedGroups = $true
            }

            if ($EmitProgressEvents -and $startedGroups) {
                [PSCustomObject]@{
                    StructuredDiagnosticProgressEvent = $true
                    EventId = [guid]::NewGuid().ToString('N')
                    Node = $nodeResult.Node
                    GroupId = $null
                    Status = 'Running'
                    CompletedCount = $groupManifestResults.Count
                    TotalCount = $groupCount
                    RemainingGroups = @($pending | ForEach-Object { $_.Group.Id }) + @($queued.ToArray() | ForEach-Object { $_.Id })
                    RunningGroups = @($pending | Where-Object Worker | ForEach-Object { $_.Group.Id })
                    QueuedGroups = @($queued.ToArray() | ForEach-Object { $_.Id })
                    DurationSeconds = ([DateTime]::UtcNow - $started).TotalSeconds
                }
            }

            foreach ($entry in @($pending.ToArray())) {
                $status = $entry.Status
                $receivedResults = @()
                $jobCompleted = $false
                if ($entry.Worker) {
                    $state = $entry.Worker.PowerShell.InvocationStateInfo.State
                    $stopWorker = $false
                    if ($entry.Worker.Invocation.IsCompleted) {
                        $jobCompleted = $state -eq 'Completed'
                        if (-not $jobCompleted) {
                            $entry.FailureMessage = 'Group worker ended without a collector result: {0}.' -f $state
                            $stopWorker = $true
                        }
                    }
                    elseif ([DateTime]::UtcNow -ge $entry.Deadline) {
                        $stopWorker = $true
                        $status = 'TimedOut'
                        $entry.FailureMessage = 'Group exceeded its timeout of {0} seconds.' -f $entry.Group.TimeoutSeconds
                    }
                    else {
                        continue
                    }
                    $receivedResults = @(Receive-StructuredDiagnosticWorkerGroup -Worker $entry.Worker -Stop:$stopWorker)
                    if ($stopWorker) {
                        Remove-StructuredDiagnosticWorker -Worker $entry.Worker
                        $workers.Remove($entry.Worker)
                    }
                }
                $collectorResults = [System.Collections.ArrayList]::new()
                $reportedResults = @($receivedResults | Where-Object { $_.PSObject.Properties.Name -contains 'CollectorId' })
                if ($jobCompleted -and $reportedResults.Count -gt 0) {
                    foreach ($result in $reportedResults) {
                        [void]$collectorResults.Add(($result | Select-Object CollectorId, Status, RelativePath, RecordCount, DurationSeconds, FailureMessage, OutputArtifacts, Truncated))
                    }
                }
                else {
                    foreach ($collector in $entry.Group.Collectors) {
                        $result = $reportedResults | Where-Object { $_.CollectorId -eq $collector.Id } | Select-Object -First 1
                        if (-not $result) {
                            $result = [PSCustomObject]@{
                                CollectorId = $collector.Id
                                Status = $status
                                RelativePath = $collector.RelativePath
                                RecordCount = 0
                                DurationSeconds = ([DateTime]::UtcNow - $entry.Started).TotalSeconds
                                FailureMessage = $entry.FailureMessage
                                OutputArtifacts = @()
                                Truncated = $false
                            }
                        }
                        [void]$collectorResults.Add(($result | Select-Object CollectorId, Status, RelativePath, RecordCount, DurationSeconds, FailureMessage, OutputArtifacts, Truncated))
                    }
                }

                $groupStatus = $status
                if ($jobCompleted -and $reportedResults.Count -gt 0) {
                    $collectorStatuses = $collectorResults.Status
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
                    elseif ($collectorStatuses -contains 'CommandNotAvailable') {
                        $groupStatus = 'CommandNotAvailable'
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
                $pending.Remove($entry)
                if ($EmitProgressEvents) {
                    $remainingGroups = @($pending | ForEach-Object { $_.Group.Id }) + @($queued.ToArray() | ForEach-Object { $_.Id })
                    [PSCustomObject]@{
                        StructuredDiagnosticProgressEvent = $true
                        EventId = [guid]::NewGuid().ToString('N')
                        Node = $nodeResult.Node
                        GroupId = $groupResult.GroupId
                        Status = $groupResult.Status
                        CompletedCount = $groupManifestResults.Count
                        TotalCount = $groupCount
                        RemainingGroups = $remainingGroups
                        RunningGroups = @($pending | Where-Object Worker | ForEach-Object { $_.Group.Id })
                        QueuedGroups = @($queued.ToArray() | ForEach-Object { $_.Id })
                        DurationSeconds = $groupResult.DurationSeconds
                    }
                }
            }
            if ($queued.Count -gt 0 -and $pending.Count -lt 2) {
                continue
            }
            if ($pending.Count -gt 0) {
                if ([DateTime]::UtcNow -ge $nextProgressUpdate) {
                    $pendingGroupIds = @($pending | ForEach-Object { $_.Group.Id })
                    Trace-Output -Level:Verbose -Message (
                        "Structured diagnostic collection is still running on '{0}' ({1}/{2} groups complete). Running: {3}. Queued: {4}." -f
                        $nodeResult.Node, $groupManifestResults.Count, $groupCount, ($pendingGroupIds -join ', '), $queued.Count
                    )
                    $nextProgressUpdate = [DateTime]::UtcNow.Add($progressInterval)
                }
                Start-Sleep -Milliseconds 100
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
        foreach ($worker in $workers) {
            try {
                Remove-StructuredDiagnosticWorker -Worker $worker
            }
            catch {
                $_ | Trace-Exception
                $_ | Write-Error -ErrorAction Continue
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

    $collectionContext = @{}
    foreach ($collector in $group.Collectors) {
        $started = [DateTime]::UtcNow
        $writer = $null
        $collect = {
            param([object[]]$ArgumentList = @())
            $ErrorActionPreference = 'Stop'
            & $collector.Collect @ArgumentList
        }
        $result = [PSCustomObject]@{
            GroupId = $group.Id
            CollectorId = $collector.Id
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
            elseif ($collector.TestAvailable -and -not (& $collector.TestAvailable)) {
                $result.Status = 'Unavailable'
                $result.FailureMessage = 'Collector {0} is not applicable on this host.' -f $collector.Id
            }
            elseif ($collector.Kind -eq 'FileSet') {
                & $collect -ArgumentList @($OutputRoot, $Format) | ForEach-Object {
                    $result.OutputArtifacts += $_
                    if ($_.Status -eq 'Success') {
                        $result.RecordCount++
                    }
                    $result.Truncated = $result.Truncated -or $_.Truncated
                }
                $failures = @($result.OutputArtifacts | Where-Object Status -eq 'Failed')
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
                        & $collect -ArgumentList @($timeFrame, $collectionContext) | ForEach-Object {
                            Write-StructuredDiagnosticArtifactRecord -Writer $writer -Record $_ `
                                -ExcludedProperties $collector.ExcludedProperties -FormatDateTime -TimeFrame $timeFrame
                        }
                    }
                    else {
                        & $collect -ArgumentList @($collectionContext) | ForEach-Object {
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
                    if ($writer.RecordCount -eq 0 -and $_.Exception -is [System.Management.Automation.CommandNotFoundException]) {
                        $result.Status = 'CommandNotAvailable'
                        Trace-Output -Level:Verbose -Message ('[{0}/{1}] Collector command is unavailable: {2}' -f $group.Id, $collector.Id, $_.Exception.Message)
                    }
                    elseif ($eventUnavailable -or $expectedUnavailable) {
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
                if ($result.Status -ne 'CommandNotAvailable') {
                    Close-StructuredDiagnosticArtifactWriter -Writer $writer
                    $result.RecordCount = $writer.RecordCount
                    $result.OutputArtifacts = @($collector.RelativePath)
                }
            }
        }
        catch {
            $result.Status = 'Failed'
            $result.FailureMessage = $_.Exception.Message
            if ($result.RecordCount -gt 0) {
                $result.Status = 'PartialSuccess'
            }
            elseif ($_.Exception -is [System.Management.Automation.CommandNotFoundException]) {
                $result.Status = 'CommandNotAvailable'
            }
            if ($result.Status -eq 'CommandNotAvailable') {
                Trace-Output -Level:Verbose -Message ('[{0}/{1}] Collector command is unavailable: {2}' -f $group.Id, $collector.Id, $_.Exception.Message)
            }
            else {
                $_ | Trace-Exception
                Write-Error -Message ('[{0}/{1}] {2}' -f $group.Id, $collector.Id, $_.Exception.Message) -ErrorAction Continue
            }
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

# ===================================
#     Collection Helper Functions
# ===================================

function Get-StructuredDiagnosticCachedValue {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Cache,

        [Parameter(Mandatory = $true)]
        [string]$Key,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Collect
    )

    if ($Cache.ContainsKey($Key)) {
        return $Cache[$Key]
    }

    $ErrorActionPreference = 'Stop'
    # Capture records as they stream, but only cache a completed enumeration.
    Invoke-Command -ScriptBlock $Collect -OutVariable values -ErrorAction Stop
    $Cache[$Key] = $values
}

# Recursively converts PowerShell and CIM objects into JSON-safe records with bounded depth.
# Scalar children are handled inline to avoid recursive parameter-binding overhead.
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
        [switch]$FormatDateTime,

        [Parameter()]
        [string]$TimeFrame
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

    # Dictionaries are also enumerable; reserve the array path for non-dictionary collections.
    if ($InputObject -isnot [System.Collections.IDictionary] -and $InputObject -is [System.Collections.IEnumerable]) {
        $items = @(foreach ($item in $InputObject) {
            if ($FormatDateTime -and ($item -is [DateTime] -or $item -is [DateTimeOffset])) {
                $item.ToString('o')
            }
            elseif ($null -eq $item -or $item -is [string] -or $item -is [ValueType]) {
                $item
            }
            else {
                ConvertTo-StructuredDiagnosticRecord -InputObject $item -Depth ($Depth + 1) -ExcludedProperties $ExcludedProperties -FormatDateTime:$FormatDateTime
            }
        })
        return ,$items
    }

    $excluded = @('CimClass', 'CimInstanceProperties', 'CimSystemProperties', 'CimSession') + $ExcludedProperties
    $record = [ordered]@{}
    if ($InputObject -is [System.Collections.IDictionary]) {
        # Map allowed dictionary keys to record properties, preserving their enumeration order.
        foreach ($key in $InputObject.Keys) {
            if ($key -notin $excluded) {
                $value = $InputObject[$key]
                $record[$key] = if ($FormatDateTime -and ($value -is [DateTime] -or $value -is [DateTimeOffset])) {
                    $value.ToString('o')
                }
                elseif ($null -eq $value -or $value -is [string] -or $value -is [ValueType]) {
                    $value
                }
                else {
                    ConvertTo-StructuredDiagnosticRecord -InputObject $value -Depth ($Depth + 1) -ExcludedProperties $ExcludedProperties -FormatDateTime:$FormatDateTime
                }
            }
        }
    }
    else {
        # Read allowed PowerShell/CIM properties once, recursing only into complex values.
        foreach ($property in $InputObject.PSObject.Properties) {
            if ($property.IsGettable -and $property.Name -notin $excluded) {
                $value = $property.Value
                $record[$property.Name] = if ($FormatDateTime -and ($value -is [DateTime] -or $value -is [DateTimeOffset])) {
                    $value.ToString('o')
                }
                elseif ($null -eq $value -or $value -is [string] -or $value -is [ValueType]) {
                    $value
                }
                else {
                    ConvertTo-StructuredDiagnosticRecord -InputObject $value -Depth ($Depth + 1) -ExcludedProperties $ExcludedProperties -FormatDateTime:$FormatDateTime
                }
            }
        }
    }
    if ($PSBoundParameters.ContainsKey('TimeFrame')) {
        # Match Add-Member -Force: replace an existing field and append it last.
        $record.Remove('TimeFrame')
        $record['TimeFrame'] = $TimeFrame
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
    try {
        if ($Format -eq 'Json') {
            $stream.WriteLine('[')
        }
        $writer = [PSCustomObject]@{
            Path = $Path
            TemporaryPath = $temporaryPath
            Format = $Format
            Stream = $stream
            RecordCount = 0
            MaximumBytes = $MaximumBytes
            BytesWritten = if ($Format -eq 'Json') { 2L } else { 0L }
        }
        return $writer
    }
    catch {
        $stream.Dispose()
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction Stop
        throw
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
        [string[]]$ExcludedProperties = @(),

        [Parameter()]
        [switch]$FormatDateTime,

        [Parameter()]
        [string]$TimeFrame
    )

    if ($Writer.Format -eq 'Text') {
        $line = [string]$Record
        $recordBytes = [System.Text.Encoding]::UTF8.GetByteCount($line + [Environment]::NewLine)
        if ($Writer.MaximumBytes -gt 0 -and ($Writer.BytesWritten + $recordBytes) -gt $Writer.MaximumBytes) {
            throw 'StructuredDiagnosticArtifactSizeLimitReached'
        }
        $Writer.Stream.WriteLine($line)
        $Writer.BytesWritten += $recordBytes
        $Writer.RecordCount++
        return
    }

    if ($PSBoundParameters.ContainsKey('TimeFrame')) {
        $plainRecord = ConvertTo-StructuredDiagnosticRecord -InputObject $Record `
            -ExcludedProperties $ExcludedProperties -FormatDateTime:$FormatDateTime -TimeFrame $TimeFrame
    }
    else {
        $plainRecord = ConvertTo-StructuredDiagnosticRecord -InputObject $Record `
            -ExcludedProperties $ExcludedProperties -FormatDateTime:$FormatDateTime
    }
    if ($PSBoundParameters.ContainsKey('TimeFrame') -and $plainRecord -isnot [PSCustomObject]) {
        $plainRecord | Add-Member -NotePropertyName TimeFrame -NotePropertyValue $TimeFrame -Force
    }
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
        [DateTime]$ToDate
    )

    $log = Get-WinEvent -ListLog $LogName -ErrorAction Stop
    if (-not $log.IsEnabled) {
        throw "Event log '$LogName' is disabled."
    }

    $filter = @{
        LogName = $LogName
        StartTime = $FromDate
        EndTime = $ToDate
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

# Keep each worker in a separate process so a hung group can be terminated.
function New-StructuredDiagnosticWorker {
    [CmdletBinding()]
    param ()

    $processInstance = [System.Management.Automation.Runspaces.PowerShellProcessInstance]::new()
    $runspace = $null
    try {
        $runspace = [runspacefactory]::CreateOutOfProcessRunspace($null, $processInstance)
        $runspace.Open()
        return @{
            ProcessInstance = $processInstance
            Runspace = $runspace
            PowerShell = $null
            Input = $null
            Output = $null
            Invocation = $null
        }
    }
    catch {
        $processInstance.Dispose()
        if ($runspace) { $runspace.Dispose() }
        throw
    }
}

function Start-StructuredDiagnosticWorkerGroup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]$Worker,
        [Parameter(Mandatory = $true)][string]$GroupId,
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [Parameter(Mandatory = $true)][string]$Format,
        [Parameter(Mandatory = $true)][string]$ModulePath,
        [Parameter(Mandatory = $true)][DateTime]$FromDate,
        [Parameter(Mandatory = $true)][DateTime]$ToDate,
        [Parameter()][switch]$IncludeLogs
    )

    $Worker.PowerShell = [powershell]::Create()
    $Worker.PowerShell.Runspace = $Worker.Runspace
    $Worker.Input = [System.Management.Automation.PSDataCollection[psobject]]::new()
    $Worker.Output = [System.Management.Automation.PSDataCollection[psobject]]::new()
    $Worker.Input.Complete()
    $scriptBlock = {
        param($groupId, $outputRoot, $format, $modulePath, $fromDate, $toDate, $includeLogs)
        $ErrorActionPreference = 'Stop'
        if (-not (Get-Module -Name SdnDiag.StructuredDiagnostics.Collectors)) {
            Import-Module $modulePath -Global -ErrorAction Stop
        }
        Invoke-StructuredDiagnosticCollectorGroup -GroupId $groupId -OutputRoot $outputRoot -Format $format `
            -FromDate $fromDate -ToDate $toDate -IncludeLogs:$includeLogs
    }
    $null = $Worker.PowerShell.AddScript($scriptBlock.ToString(), $true).
        AddArgument($GroupId).AddArgument($OutputRoot).AddArgument($Format).AddArgument($ModulePath).
        AddArgument($FromDate).AddArgument($ToDate).AddArgument($IncludeLogs.IsPresent)
    $Worker.Invocation = $Worker.PowerShell.BeginInvoke($Worker.Input, $Worker.Output)
}

function Receive-StructuredDiagnosticWorkerGroup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]$Worker,
        [Parameter()][switch]$Stop
    )

    if ($Stop) {
        Stop-StructuredDiagnosticWorker -Worker $Worker
    }
    try {
        $null = $Worker.PowerShell.EndInvoke($Worker.Invocation)
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error -ErrorAction Continue
    }
    foreach ($errorRecord in $Worker.PowerShell.Streams.Error) {
        $errorRecord | Write-Error -ErrorAction Continue
    }
    foreach ($warningRecord in $Worker.PowerShell.Streams.Warning) {
        Trace-Output -Level Warning -Message $warningRecord.Message
    }
    foreach ($verboseRecord in $Worker.PowerShell.Streams.Verbose) {
        Trace-Output -Level Verbose -Message $verboseRecord.Message
    }
    try {
        $Worker.Output.ReadAll()
    }
    finally {
        $Worker.PowerShell.Dispose()
        $Worker.Input.Dispose()
        $Worker.Output.Dispose()
        $Worker.PowerShell = $null
        $Worker.Input = $null
        $Worker.Output = $null
        $Worker.Invocation = $null
    }
}

function Stop-StructuredDiagnosticWorker {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]$Worker
    )

    $process = $Worker.ProcessInstance.Process
    # Close the transport first to avoid remoting's wait for a dead worker.
    if ($Worker.Runspace.RunspaceStateInfo.State -eq 'Opened') {
        $Worker.Runspace.CloseAsync()
    }
    if (-not $process.HasExited) {
        $process.Kill()
        if (-not $process.WaitForExit(5000)) {
            throw [System.TimeoutException]::new('The structured diagnostic worker process did not exit.')
        }
    }
}

function Remove-StructuredDiagnosticWorker {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]$Worker
    )

    try {
        Stop-StructuredDiagnosticWorker -Worker $Worker
    }
    finally {
        try {
            if ($Worker.PowerShell) { $Worker.PowerShell.Dispose() }
            if ($Worker.Input) { $Worker.Input.Dispose() }
            if ($Worker.Output) { $Worker.Output.Dispose() }
        }
        finally {
            try {
                $Worker.Runspace.Dispose()
            }
            finally {
                $Worker.ProcessInstance.Dispose()
            }
        }
    }
}