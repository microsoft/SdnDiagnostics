# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Import-Module -Name $PSScriptRoot\SdnDiag.Utilities.psm1 -ErrorAction Stop
Import-Module -Name $PSScriptRoot\SdnDiag.StructuredDiagnostics.Collectors.psm1 -ErrorAction Stop

function Invoke-StructuredDiagnostics {
    <#
    .SYNOPSIS
        Collects structured diagnostics from Windows Server or Azure Local computers.
    .DESCRIPTION
        Runs the separate collector catalog on verified Hyper-V hosts without Network Controller discovery or SDN role detection.
        Uses SdnDiagnostics remote sessions, file-copy and cleanup helpers. Remote targets require
        SdnDiagnostics and WinRM access; local collection does not require WinRM.
    .PARAMETER ComputerName
        Computers to collect from. Defaults to the local computer.
        Duplicate short host names are warned and skipped case-insensitively, preserving the first occurrence.
    .PARAMETER OutputDirectory
        SdnDataCollection directory under which StructuredDiagnostics\<ComputerName> output is written.
    .PARAMETER Format
        Artifact serialization format. Manifests are always JSON.
    .PARAMETER FromDate
        Beginning of the event and performance collection window.
    .PARAMETER ToDate
        End of the collection window. Performance history uses relative duration buckets.
    .PARAMETER IncludeLogs
        Includes Network ATC events and bounded network setup-log copies.
    .PARAMETER Credential
        Credentials for remote sessions, file retrieval and cleanup.
    .EXAMPLE
        Invoke-StructuredDiagnostics -OutputDirectory C:\Temp
    .EXAMPLE
        Invoke-StructuredDiagnostics -ComputerName 'Host01','Host02' -IncludeLogs -Credential (Get-Credential)
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$ComputerName = @($env:COMPUTERNAME),

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$OutputDirectory = (Get-WorkingDirectory),

        [Parameter()]
        [ValidateSet('Json', 'Ndjson')]
        [string]$Format = 'Json',

        [Parameter()]
        [DateTime]$FromDate = (Get-Date).AddHours(-4),

        [Parameter()]
        [DateTime]$ToDate = (Get-Date),

        [Parameter()]
        [switch]$IncludeLogs,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    if ($FromDate -gt $ToDate) {
        throw 'FromDate must be earlier than or equal to ToDate.'
    }

    $ComputerName = @(Get-StructuredDiagnosticTarget -ComputerName $ComputerName)
    $started = [DateTime]::UtcNow
    $collectionId = Split-Path -Path $OutputDirectory -Leaf
    if ([string]::IsNullOrWhiteSpace($collectionId)) {
        throw 'OutputDirectory must identify a SdnDataCollection directory.'
    }
    $collectionRoot = Join-Path $OutputDirectory 'StructuredDiagnostics'
    $nodeResults = [System.Collections.ArrayList]::new()
    $collectionJobs = [System.Collections.ArrayList]::new()
    $nodeDirectoryNames = @{}
    foreach ($computer in $ComputerName) {
        $name = [regex]::Replace($computer.Trim(), '[\\/:*?"<>|]', '_').Trim([char[]]@('.', ' '))
        if ([string]::IsNullOrWhiteSpace($name) -or $nodeDirectoryNames.Values -contains $name) {
            throw 'ComputerName must resolve to a nonempty, unique output directory name.'
        }
        $nodeDirectoryNames[$computer] = $name
    }

    try {
        if (Test-Path -LiteralPath $collectionRoot) {
            throw 'The structured diagnostics output directory already exists.'
        }
        if (-not (Initialize-DataCollection -FilePath $collectionRoot -MinimumMB 100)) {
            throw 'Unable to initialize structured diagnostic collection.'
        }
        $moduleVersion = (Get-Module -Name SdnDiagnostics -All | Select-Object -First 1).Version.ToString()
        $localComputers = [System.Collections.ArrayList]::new()
        $remoteComputers = [System.Collections.ArrayList]::new()
        foreach ($computer in $ComputerName) {
            if (Test-ComputerNameIsLocal -ComputerName $computer) {
                [void]$localComputers.Add($computer)
            }
            else {
                [void]$remoteComputers.Add($computer)
            }
        }

        $localStartFailures = @{}
        $remoteInvocationFailure = $null
        if ($remoteComputers.Count -gt 0) {
            try {
                "Starting structured diagnostics on remote computers: {0}" -f ($remoteComputers -join ', ') | Trace-Output
                $remoteJob = Invoke-PSRemoteCommand -ComputerName @($remoteComputers) -Credential $Credential `
                    -ImportModuleOnRemoteSession $true -AsJob -ErrorAction Stop -ScriptBlock {
                        param($collectionId, $format, $fromDate, $toDate, $includeLogs)
                        $module = Get-Module -Name SdnDiagnostics -All | Select-Object -First 1
                        if (-not $module) {
                            $module = Import-Module -Name SdnDiagnostics -PassThru -ErrorAction Stop |
                                Where-Object Name -eq 'SdnDiagnostics' | Select-Object -First 1
                        }
                        if (-not $module) {
                            throw 'Unable to import the SdnDiagnostics module on the remote computer.'
                        }
                        $structuredModulePath = Join-Path $module.ModuleBase 'modules\SdnDiag.StructuredDiagnostics.psm1'
                        $structuredModule = Import-Module -Name $structuredModulePath -PassThru -ErrorAction Stop |
                            Where-Object Name -eq 'SdnDiag.StructuredDiagnostics' | Select-Object -First 1
                        if (-not $structuredModule) {
                            throw "Unable to import the SdnDiag.StructuredDiagnostics module from '$structuredModulePath'."
                        }
                        return & $structuredModule {
                            param($collectionId, $format, $fromDate, $toDate, $includeLogs, $moduleVersion)
                            Confirm-IsServer
                            $stagingPath = Join-Path (Get-WorkingDirectory) "StructuredDiagnostics_Staging\$collectionId"
                            $nodeResult = $null
                            Invoke-StructuredDiagnosticCollection -OutputRoot $stagingPath -CollectionId $collectionId `
                                -ModuleVersion $moduleVersion -Format $format -FromDate $fromDate -ToDate $toDate `
                                -IncludeLogs:$includeLogs -EmitProgressEvents | ForEach-Object {
                                    if ($_.StructuredDiagnosticProgressEvent) {
                                        $_
                                    }
                                    else {
                                        $nodeResult = $_
                                    }
                                }
                            if (-not $nodeResult) {
                                throw 'The remote structured diagnostic collector returned no final result.'
                            }
                            $nodeResult.ManifestPath = Join-Path $stagingPath 'CollectionManifest.json'
                            return $nodeResult
                        } $collectionId $format $fromDate $toDate $includeLogs $module.Version.ToString()
                    } -ArgumentList @($collectionId, $Format, $FromDate, $ToDate, $IncludeLogs.IsPresent)
                if (-not $remoteJob -or -not $remoteJob.Name) {
                    throw 'Unable to start the remote structured diagnostic collection job.'
                }
                [void]$collectionJobs.Add($remoteJob)
            }
            catch {
                $remoteInvocationFailure = $_
                $_ | Trace-Exception
            }
        }

        foreach ($computer in $localComputers) {
            $nodeOutputRoot = Join-Path $collectionRoot $nodeDirectoryNames[$computer]
            try {
                "Starting structured diagnostics on local computer: {0}" -f $computer | Trace-Output
                $localJob = Start-Job -Name ("SdnDiag-Structured-{0}" -f (Get-Random)) -ScriptBlock {
                    param($structuredModulePath, $outputRoot, $collectionId, $format, $fromDate, $toDate, $includeLogs, $moduleVersion, $requestedNode)
                    $structuredModule = Import-Module -Name $structuredModulePath -PassThru -ErrorAction Stop |
                        Where-Object Name -eq 'SdnDiag.StructuredDiagnostics' | Select-Object -First 1
                    if (-not $structuredModule) {
                        throw "Unable to import the SdnDiag.StructuredDiagnostics module from '$structuredModulePath'."
                    }
                    return & $structuredModule {
                        param($outputRoot, $collectionId, $format, $fromDate, $toDate, $includeLogs, $moduleVersion, $requestedNode)
                        Confirm-IsServer
                        $nodeResult = $null
                        Invoke-StructuredDiagnosticCollection -OutputRoot $outputRoot -CollectionId $collectionId `
                            -ModuleVersion $moduleVersion -Format $format -FromDate $fromDate -ToDate $toDate `
                            -IncludeLogs:$includeLogs -EmitProgressEvents | ForEach-Object {
                                if ($_.StructuredDiagnosticProgressEvent) {
                                    $_
                                }
                                else {
                                    $nodeResult = $_
                                }
                            }
                        if (-not $nodeResult) {
                            throw 'The local structured diagnostic collector returned no final result.'
                        }
                        $nodeResult.ManifestPath = Join-Path $outputRoot 'CollectionManifest.json'
                        $nodeResult | Add-Member -NotePropertyName RequestedNode -NotePropertyValue $requestedNode -Force
                        return $nodeResult
                    } $outputRoot $collectionId $format $fromDate $toDate $includeLogs $moduleVersion $requestedNode
                } -ArgumentList @($PSCommandPath, $nodeOutputRoot, $collectionId, $Format, $FromDate, $ToDate, $IncludeLogs.IsPresent, $moduleVersion, $computer)
                [void]$collectionJobs.Add($localJob)
            }
            catch {
                $localStartFailures[$computer] = $_
                $_ | Trace-Exception
                $_ | Write-Error -ErrorAction Continue
            }
        }

        $jobOutput = @()
        if ($collectionJobs.Count -gt 0) {
            $progressUpdateScript = {
                param($jobs, $reportedEventIds)
                Write-StructuredDiagnosticProgressUpdates -Jobs $jobs -ReportedEventIds $reportedEventIds
            }
            $progressStatusScript = {
                param($jobs)
                (Get-StructuredDiagnosticProgressSnapshot -Jobs $jobs).Status
            }
            $progressPercentScript = {
                param($jobs)
                (Get-StructuredDiagnosticProgressSnapshot -Jobs $jobs).PercentComplete
            }
            $jobOutput = @(Wait-PSJob -Name @($collectionJobs.Name) -Activity 'Structured diagnostics' `
                -ExecutionTimeOut 1800 -ProgressStatusScript $progressStatusScript `
                -ProgressPercentScript $progressPercentScript -ProgressUpdateScript $progressUpdateScript -ShowProgress)
        }

        $collectionResults = @($jobOutput | Where-Object {
            $_.PSObject.Properties.Name -contains 'Status' -and
            $_.PSObject.Properties.Name -contains 'ManifestPath'
        })
        $localResults = @($collectionResults | Where-Object {
            $_.PSObject.Properties.Name -contains 'RequestedNode'
        })
        foreach ($computer in $localComputers) {
            $nodeResult = $localResults | Where-Object RequestedNode -ieq $computer | Select-Object -First 1
            if ($localStartFailures.ContainsKey($computer) -or -not $nodeResult) {
                $failureMessage = if ($localStartFailures.ContainsKey($computer)) {
                    $localStartFailures[$computer].Exception.Message
                }
                else {
                    "Computer '$computer' returned no structured diagnostic collection result."
                }
                [void]$nodeResults.Add([PSCustomObject]@{
                    Node = $computer
                    Status = 'Failed'
                    ManifestPath = $null
                    FailureMessage = $failureMessage
                })
            }
            else {
                [void]$nodeResults.Add([PSCustomObject]@{
                    Node = $computer
                    Status = $nodeResult.Status
                    ManifestPath = Join-Path $collectionRoot "$($nodeDirectoryNames[$computer])\CollectionManifest.json"
                    FailureMessage = $nodeResult.FailureMessage
                })
            }
        }

        if ($remoteComputers.Count -gt 0) {
            $remoteResults = @($collectionResults | Where-Object {
                $_.PSObject.Properties.Name -notcontains 'RequestedNode'
            })
            foreach ($computer in $remoteComputers) {
                $nodeOutputRoot = Join-Path $collectionRoot $nodeDirectoryNames[$computer]
                try {
                    if ($remoteInvocationFailure) {
                        throw $remoteInvocationFailure
                    }
                    $nodeResult = $remoteResults | Where-Object { $_.PSComputerName -ieq $computer } | Select-Object -First 1
                    if (-not $nodeResult -and $remoteComputers.Count -eq 1 -and $remoteResults.Count -eq 1) {
                        $nodeResult = $remoteResults[0]
                    }
                    if (-not $nodeResult -or -not $nodeResult.ManifestPath) {
                        throw "Computer '$computer' returned no structured diagnostic collection result."
                    }
                    $stagingPath = Split-Path -Parent $nodeResult.ManifestPath
                    try {
                        $null = New-Item -Path $nodeOutputRoot -ItemType Directory -Force -ErrorAction Stop
                        Copy-FileFromRemoteComputer -ComputerName $computer -Credential $Credential `
                            -Path (Join-Path $stagingPath '*') -Destination $nodeOutputRoot -Recurse -Force -ErrorAction Stop
                        if (-not (Test-Path -LiteralPath (Join-Path $nodeOutputRoot 'CollectionManifest.json') -PathType Leaf)) {
                            throw "The manifest for '$computer' was not retrieved."
                        }
                    }
                    finally {
                        # Retrieval is best effort; always attempt staging cleanup, even if some artifacts were not retrieved.
                        Clear-SdnWorkingDirectory -ComputerName $computer -Credential $Credential -Path $stagingPath -Recurse -ErrorAction Stop
                    }
                    [void]$nodeResults.Add([PSCustomObject]@{
                        Node = $computer
                        Status = $nodeResult.Status
                        ManifestPath = Join-Path $nodeOutputRoot 'CollectionManifest.json'
                        FailureMessage = $nodeResult.FailureMessage
                    })
                }
                catch {
                    $_ | Trace-Exception
                    $_ | Write-Error -ErrorAction Continue
                    [void]$nodeResults.Add([PSCustomObject]@{
                        Node = $computer
                        Status = 'Failed'
                        ManifestPath = $null
                        FailureMessage = $_.Exception.Message
                    })
                }
            }
        }

        $usableNodes = @($nodeResults | Where-Object { $_.Status -in @('Completed', 'CompletedWithFailures') })
        $status = if ($usableNodes.Count -eq 0) { 'Failed' }
            elseif (@($nodeResults | Where-Object Status -ne 'Completed').Count -gt 0) { 'CompletedWithFailures' }
            else { 'Completed' }
        $manifestPath = Join-Path $collectionRoot 'ClusterCollectionManifest.json'
        $result = [PSCustomObject]@{
            CollectionId = $collectionId
            Status = $status
            OutputRoot = $collectionRoot
            ManifestPath = $manifestPath
            Format = $Format
            FromDateUtc = $FromDate.ToUniversalTime().ToString('o')
            ToDateUtc = $ToDate.ToUniversalTime().ToString('o')
            StartedUtc = $started.ToString('o')
            CompletedUtc = [DateTime]::UtcNow.ToString('o')
            Nodes = @($nodeResults.ToArray())
        }
        $result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $manifestPath -Encoding UTF8 -ErrorAction Stop
        if ($status -eq 'Failed') {
            throw 'Structured diagnostics failed on every requested computer. See the collection manifest for details.'
        }
        return $result
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error -ErrorAction Stop
    }
    finally {
        foreach ($job in $collectionJobs) {
            try {
                Remove-Job -Job $job -Force -ErrorAction Stop
            }
            catch {
                $_ | Trace-Exception
                $_ | Write-Error -ErrorAction Continue
            }
        }
    }
}

function Get-StructuredDiagnosticProgressEvents {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Job,

        [Parameter(Mandatory = $true)]
        [object]$ChildJob
    )

    $progressEvents = @($ChildJob.Output | Where-Object {
        $_.PSObject.Properties.Name -contains 'StructuredDiagnosticProgressEvent' -and
        $_.StructuredDiagnosticProgressEvent
    })
    if ($progressEvents.Count -eq 0) {
        $progressEvents = @($Job.Output | Where-Object {
            $_.PSObject.Properties.Name -contains 'StructuredDiagnosticProgressEvent' -and
            $_.StructuredDiagnosticProgressEvent -and
            ($_.PSComputerName -ieq $ChildJob.Location -or $_.Node -ieq $ChildJob.Location)
        })
    }

    return $progressEvents
}

function Write-StructuredDiagnosticProgressUpdates {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Jobs,

        [Parameter(Mandatory = $true)]
        [hashtable]$ReportedEventIds
    )

    foreach ($job in $Jobs) {
        foreach ($childJob in @($job.ChildJobs)) {
            $progressEvents = @(Get-StructuredDiagnosticProgressEvents -Job $job -ChildJob $childJob)
            foreach ($progressEvent in $progressEvents) {
                if (-not $progressEvent.GroupId -or [string]::IsNullOrWhiteSpace($progressEvent.EventId) -or
                    $ReportedEventIds.ContainsKey($progressEvent.EventId)) {
                    continue
                }

                $ReportedEventIds[$progressEvent.EventId] = $true
                $node = if ($progressEvent.Node) {
                    $progressEvent.Node
                }
                elseif ($progressEvent.PSComputerName) {
                    $progressEvent.PSComputerName
                }
                else {
                    $childJob.Location
                }
                Trace-Output -ComputerName $node -Message (
                    "Completed structured diagnostics group {0} ({1}/{2}, {3})" -f
                    $progressEvent.GroupId, $progressEvent.CompletedCount,
                    $progressEvent.TotalCount, $progressEvent.Status
                )
            }
        }
    }
}

function Get-StructuredDiagnosticProgressSnapshot {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Jobs
    )

    $nodeStatuses = [System.Collections.ArrayList]::new()
    $completedCount = 0
    $totalCount = 0
    foreach ($job in $Jobs) {
        foreach ($childJob in @($job.ChildJobs)) {
            $progressEvents = @(Get-StructuredDiagnosticProgressEvents -Job $job -ChildJob $childJob)
            if ($progressEvents.Count -gt 0) {
                $latestEvent = $progressEvents[-1]
                $remainingGroups = @($latestEvent.RemainingGroups)
                $remainingPreview = @($remainingGroups | Select-Object -First 2)
                $remainingText = if ($remainingGroups.Count -eq 0) {
                    'none'
                }
                elseif ($remainingGroups.Count -gt $remainingPreview.Count) {
                    "{0}, +{1} more" -f ($remainingPreview -join ', '), ($remainingGroups.Count - $remainingPreview.Count)
                }
                else {
                    $remainingPreview -join ', '
                }
                $node = if ($latestEvent.Node) {
                    $latestEvent.Node
                }
                elseif ($latestEvent.PSComputerName) {
                    $latestEvent.PSComputerName
                }
                else {
                    $childJob.Location
                }
                if ($null -ne $latestEvent.CompletedCount -and $null -ne $latestEvent.TotalCount) {
                    $completedCount += $latestEvent.CompletedCount
                    $totalCount += $latestEvent.TotalCount
                    $executionText = ''
                    if ($latestEvent.PSObject.Properties.Name -contains 'RunningGroups' -and
                        $latestEvent.PSObject.Properties.Name -contains 'QueuedGroups') {
                        $runningText = if (@($latestEvent.RunningGroups).Count -gt 0) {
                            $latestEvent.RunningGroups -join ', '
                        }
                        else {
                            'none'
                        }
                        $executionText = '; running: {0}; queued: {1}' -f $runningText, @($latestEvent.QueuedGroups).Count
                    }
                    [void]$nodeStatuses.Add(("{0} {1}/{2} groups ({3}{4})" -f
                        $node, $latestEvent.CompletedCount, $latestEvent.TotalCount, $remainingText, $executionText))
                }
                elseif ($latestEvent.GroupId) {
                    [void]$nodeStatuses.Add(("{0}: completed group {1}; detailed counts unavailable" -f
                        $node, $latestEvent.GroupId))
                }
                else {
                    [void]$nodeStatuses.Add(("{0}: starting collector groups" -f $node))
                }
            }
            elseif ($childJob.State -ne 'Completed') {
                [void]$nodeStatuses.Add(("{0}: waiting for the first group update ({1})" -f
                    $childJob.Location, $childJob.State))
            }
        }
    }

    [PSCustomObject]@{
        Status = if ($nodeStatuses.Count -gt 0) { $nodeStatuses -join '; ' } else { $null }
        PercentComplete = if ($totalCount -gt 0) {
            [math]::Round(($completedCount / $totalCount) * 100, 2)
        }
        else {
            $null
        }
    }
}

function Get-StructuredDiagnosticTarget {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]$ComputerName
    )

    try {
        if ($ComputerName.Count -gt 0) {
            $seen = @{}
            foreach ($computer in $ComputerName) {
                $address = $null
                # Collapse short-name/FQDN aliases to prevent same-host staging collisions, but preserve full IPs to avoid false duplicates (no DNS lookup).
                $targetKey = if ([System.Net.IPAddress]::TryParse($computer, [ref]$address)) {
                    $address.ToString()
                }
                else {
                    ($computer -split '\.', 2)[0]
                }
                if ($seen.ContainsKey($targetKey)) {
                    Trace-Output -Level:Warning -Message (
                        "Skipping duplicate structured diagnostic target '{0}'; '{1}' was already selected." -f
                        $computer, $seen[$targetKey]
                    )
                    continue
                }
                $seen[$targetKey] = $computer
                $computer
            }
            return
        }

        if (Test-Path -LiteralPath 'HKLM:\Cluster' -ErrorAction Stop) {
            $nodes = @(Get-ClusterNode -ErrorAction Stop | Select-Object -ExpandProperty Name -Unique)
            if ($nodes.Count -eq 0) {
                throw 'The configured Windows cluster returned no host nodes.'
            }
            return $nodes
        }

        return $env:COMPUTERNAME
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error -ErrorAction Stop
    }
}