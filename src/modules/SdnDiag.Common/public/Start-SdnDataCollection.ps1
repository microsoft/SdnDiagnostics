function Start-SdnDataCollection {

    <#
    .SYNOPSIS
        Automated data collection script to pull the current configuration state in conjuction with diagnostic logs and other data points used for debugging.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER Role
        The specific SDN role(s) to collect configuration state and logs from.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER OutputDirectory
        Directory the results will be saved to. If ommitted, will default to the current working directory.
    .PARAMETER IncludeNetView
        If enabled, will execute Get-NetView on the Role(s) or ComputerName(s) defined.
    .PARAMETER IncludeLogs
        If enabled, will collect the diagnostic logs from the Role(s) or ComputerName(s) defined. Works in conjunction with the FromDate parameter.
    .PARAMETER FromDate
        Determines the start time of what logs to collect. If omitted, defaults to the last 4 hours.
    .PARAMETER ToDate
        Determines the end time of what logs to collect. Optional parameter that if ommitted, defaults to current time.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    .PARAMETER Limit
        Used in conjuction with the Role parameter to limit how many nodes per role operations are performed against. If ommitted, defaults to 16.
    .PARAMETER ConvertETW
        Optional parameter that allows you to specify if .etl trace should be converted. By default, set to $true
    .EXAMPLE
        PS> Start-SdnDataCollection -NetworkController 'Contoso-NC01' -Role Gateway,NetworkController,Server,LoadBalancerMux
    .EXAMPLE
        PS> Start-SdnDataCollection -NetworkController 'Contoso-NC01' -Role Gateway,NetworkController,Server,LoadBalancerMux -IncludeLogs
    .EXAMPLE
        PS> Start-SdnDataCollection -NetworkController 'Contoso-NC01' -Role Gateway,Server,LoadBalancerMux -IncludeLogs -FromDate (Get-Date).AddHours(-1) -Credential (Get-Credential)
    .EXAMPLE
        PS> Start-SdnDataCollection -NetworkController 'Contoso-NC01' -Role LoadBalancerMux -IncludeLogs -IncludeNetView -FromDate '2023-08-11 10:00:00 AM' -ToDate '2023-08-11 11:30:00 AM'
    #>

    [CmdletBinding(DefaultParameterSetName = 'Role')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Computer')]
        [System.String]$NetworkController = $(HostName),

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Computer')]
        [ValidateScript({
            if ($_.Scheme -ne "http" -and $_.Scheme -ne "https") {
                throw New-Object System.FormatException("Parameter is expected to be in http:// or https:// format.")
            }
            return $true
        })]
        [Uri]$NcUri,

        [Parameter(Mandatory = $true, ParameterSetName = 'Role')]
        [ValidateSet('Gateway', 'NetworkController', 'Server', 'LoadBalancerMux')]
        [String[]]$Role,

        [Parameter(Mandatory = $true, ParameterSetName = 'Computer')]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Computer')]
        [System.IO.FileInfo]$OutputDirectory = (Get-WorkingDirectory),

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Computer')]
        [Switch]$IncludeNetView,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Computer')]
        [Switch]$IncludeLogs,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Computer')]
        [DateTime]$FromDate = (Get-Date).AddHours(-4),

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Computer')]
        [DateTime]$ToDate = (Get-Date),

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Computer')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Computer')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Int]$Limit = 16,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Computer')]
        [bool]$ConvertETW = $true
    )

    $dataCollectionNodes = [System.Collections.ArrayList]::new() # need an arrayList so we can remove objects from this list
    $filteredDataCollectionNodes = @()
    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

    $dataCollectionObject = [PSCustomObject]@{
        DurationInMinutes = $null
        TotalSize         = $null
        OutputDirectory   = $null
        Role              = $null
        IncludeNetView    = $IncludeNetView
        IncludeLogs       = $IncludeLogs
        FromDate          = $FromDate.ToString()
        FromDateUTC       = $FromDate.ToUniversalTime().ToString()
        ToDate            = $ToDate.ToString()
        ToDateUTC         = $ToDate.ToUniversalTime().ToString()
        Result            = $null
    }

    $collectLogSB = {
        param([string[]]$arg0,[String]$arg1,[DateTime]$arg2,[DateTime]$arg3,[Boolean]$arg4,[Boolean]$arg5,[string[]]$arg6)
        Get-SdnDiagnosticLogFile -LogDir $arg0 -OutputDirectory $arg1 -FromDate $arg2 -ToDate $arg3 -ConvertETW $arg4 -CleanUpFiles $arg5 -FolderNameFilter $arg6
    }

    $collectConfigStateSB = {
        param([Parameter(Position = 0)][String]$Role, [Parameter(Position = 1)][String]$OutputDirectory)
        Get-SdnConfigState -Role $Role -OutputDirectory $OutputDirectory
    }

    try {
        if (-NOT ($PSBoundParameters.ContainsKey('NetworkController'))) {
            $config = Get-SdnModuleConfiguration -Role 'NetworkController'
            $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
            if (-NOT ($confirmFeatures)) {
                "The current machine is not a NetworkController, run this on NetworkController or use -NetworkController parameter to specify one" | Trace-Output -Level:Warning
                return # don't throw exception, since this is a controlled scenario and we do not need stack exception tracing
            }
        }

        [System.String]$childPath = 'SdnDataCollection_{0}' -f (Get-FormattedDateTimeUTC)
        [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath $childPath
        [System.IO.FileInfo]$workingDirectory = (Get-WorkingDirectory)
        [System.IO.FileInfo]$tempDirectory = "$(Get-WorkingDirectory)\Temp"

        # setup the directory location where files will be saved to
        "Starting SDN Data Collection" | Trace-Output

        if ($IncludeLogs) {
            $minGB = 10
        }
        else {
            $minGB = 5
        }

        if (-NOT (Initialize-DataCollection -FilePath $OutputDirectory.FullName -MinimumGB $minGB)) {
            "Unable to initialize environment for data collection" | Trace-Output -Level:Error
            return
        }

        "Results will be saved to {0}" -f $OutputDirectory.FullName | Trace-Output

        # generate a mapping of the environment
        if ($NcUri) {
            $sdnFabricDetails = Get-SdnInfrastructureInfo -NetworkController $NetworkController -Credential $Credential -NcUri $NcUri.AbsoluteUri -NcRestCredential $NcRestCredential
        }
        else {
            $sdnFabricDetails = Get-SdnInfrastructureInfo -NetworkController $NetworkController -Credential $Credential -NcRestCredential $NcRestCredential
        }

        # determine if network controller is using default logging mechanism to local devices or network share
        [xml]$clusterManifest = Get-SdnServiceFabricClusterManifest -NetworkController $NetworkController -Credential $Credential
        $fileShareWinFabEtw = $clusterManifest.ClusterManifest.FabricSettings.Section | Where-Object {$_.Name -ieq 'FileShareWinFabEtw'}
        $connectionString = $fileShareWinFabEtw.Parameter | Where-Object {$_.Name -ieq 'StoreConnectionString'}
        if ($connectionString.value) {
            # typically the network share will be in a format of file://share/path
            $diagLogNetShare = ($connectionString.value).Split(':')[1].Replace('/', '\').Trim()
            $ncNodeFolders = @()
        }

        switch ($PSCmdlet.ParameterSetName) {
            'Role' {
                foreach ($value in $Role) {
                    foreach ($node in $sdnFabricDetails[$value.ToString()]) {
                        $object = [PSCustomObject]@{
                            Role = $value
                            Name = $node
                        }

                        "{0} with role {1} added for data collection" -f $object.Name, $object.Role | Trace-Output
                        [void]$dataCollectionNodes.Add($object)
                    }
                }
            }

            'Computer' {
                foreach ($computer in $ComputerName) {
                    $computerRole = Get-SdnRole -ComputerName $computer -EnvironmentInfo $sdnFabricDetails
                    if ($computerRole) {
                        $object = [PSCustomObject]@{
                            Role = $computerRole
                            Name = $computer
                        }

                        "{0} with role {1} added for data collection" -f $object.Name, $object.Role | Trace-Output
                        [void]$dataCollectionNodes.Add($object)
                    }
                }
            }
        }

        if ($dataCollectionNodes.Count -eq 0) {
            throw New-Object System.NullReferenceException("No data nodes identified")
        }

        # once we have identified the nodes, we need to validate WinRM connectivity to the nodes
        # if we are running on PowerShell 7 or greater, we can leverage the -Parallel parameter
        # to speed up the process
        # if we are running on PowerShell 5.1, we will need to run the process in serial
        # if we have any nodes that fail the WinRM connectivity test, we will remove them from the data collection
        "Validating WinRM connectivity to {0}" -f ($dataCollectionNodes.Name -join ', ') | Trace-Output

        $nodesToRemove = [System.Collections.ArrayList]::new()
        $tncScriptBlock = {
            $tncResult = Test-NetConnection -ComputerName $_.Name -Port 5985 -InformationLevel Quiet
            if (-NOT ($tncResult)) {
                [void]$nodesToRemove.Add($_)
            }
        }

        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $dataCollectionNodes | Foreach-Object -ThrottleLimit 10 -Parallel $tncScriptBlock
        }
        else {
            $dataCollectionNodes | ForEach-Object $tncScriptBlock
        }

        if ($nodesToRemove.Count -gt 0) {
            $nodesToRemove | ForEach-Object {
                "Removing {0} from data collection due to WinRM connectivity issues" -f $_.Name | Trace-Output -Level:Warning
                [void]$dataCollectionNodes.Remove($_)
            }
        }

        $dataCollectionNodes = $dataCollectionNodes | Sort-Object -Property Name -Unique
        $groupedObjectsByRole = $dataCollectionNodes | Group-Object -Property Role

        # ensure SdnDiagnostics installed across the data nodes and versions are the same
        # depending on the state of the environment though, these may result in failure
        Install-SdnDiagnostics -ComputerName $NetworkController -ErrorAction Continue
        Install-SdnDiagnostics -ComputerName $dataCollectionNodes.Name -ErrorAction Continue

        # ensure that the NcUrl is populated before we start collecting data
        # in scenarios where certificate is not trusted or expired, we will not be able to collect data
        if (-NOT ([System.String]::IsNullOrEmpty($sdnFabricDetails.NcUrl))) {
            $slbStateInfo = Get-SdnSlbStateInformation -NcUri $sdnFabricDetails.NcUrl -Credential $NcRestCredential
            $slbStateInfo | ConvertTo-Json -Depth 100 | Out-File "$($OutputDirectory.FullName)\SlbState.Json"
            Invoke-SdnResourceDump -NcUri $sdnFabricDetails.NcUrl -OutputDirectory $OutputDirectory.FullName -Credential $NcRestCredential
            Get-SdnNetworkControllerState -NetworkController $NetworkController -OutputDirectory $OutputDirectory.FullName -Credential $Credential -NcRestCredential $NcRestCredential
        }

        Get-SdnNetworkControllerClusterInfo -NetworkController $NetworkController -OutputDirectory $OutputDirectory.FullName -Credential $Credential
        $debugInfraHealthResults = Get-SdnFabricInfrastructureResult
        if ($debugInfraHealthResults) {
            $debugInfraHealthResults | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnFabricInfrastructureResult_Summary' -FileType 'txt' -Format 'table'
            $debugInfraHealthResults | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnFabricInfrastructureResult' -FileType json -Depth 5
        }

        # enumerate through each role and collect appropriate data
        foreach ($group in $groupedObjectsByRole | Sort-Object -Property Name) {
            if ($PSCmdlet.ParameterSetName -eq 'Role') {
                if ($group.Group.Name.Count -ge $Limit) {
                    "Exceeded node limit for role {0}. Limiting nodes to the first {1} nodes" -f $group.Name, $Limit | Trace-Output -Level:Warning
                }

                $dataNodes = $group.Group.Name | Select-Object -First $Limit
            }
            else {
                $dataNodes = $group.Group.Name
            }

            "Performing cleanup of {0} directory across {1}" -f $tempDirectory.FullName, ($dataNodes -join ', ') | Trace-Output
            Clear-SdnWorkingDirectory -Path $tempDirectory.FullName -Recurse -ComputerName $dataNodes -Credential $Credential

            # add the data nodes to new variable, to ensure that we pick up the log files specifically from these nodes
            # to account for if filtering was applied
            $filteredDataCollectionNodes += $dataNodes

            "Collect configuration state details for {0} nodes: {1}" -f $group.Name, ($dataNodes -join ', ') | Trace-Output
            Invoke-PSRemoteCommand -ComputerName $dataNodes -Credential $Credential -ScriptBlock $collectConfigStateSB `
                -ArgumentList @($group.Name, $tempDirectory.FullName) -AsJob -PassThru -Activity "Collect $($group.Name) Configuration State"

            # collect any adhoc data based on the role
            switch ($group.Name) {
                'Server' {
                    Get-SdnProviderAddress -ComputerName $dataNodes -Credential $Credential `
                    | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnProviderAddress' -FileType csv

                    Get-SdnVfpVmSwitchPort -ComputerName $dataNodes -Credential $Credential `
                    | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnVfpVmSwitchPort' -FileType csv

                    Get-SdnVMNetworkAdapter -ComputerName $dataNodes -Credential $Credential -AsJob -PassThru -Timeout 900 `
                    | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnVMNetworkAdapter' -FileType csv
                }
            }

            # check to see if any network traces were captured on the data nodes previously
            "Checking for any previous network traces and moving them into {0}" -f $tempDirectory.FullName | Trace-Output
            Invoke-PSRemoteCommand -ComputerName $dataNodes -Credential $Credential -ScriptBlock $collectLogSB `
            -ArgumentList @("$($workingDirectory.FullName)\NetworkTraces", $tempDirectory.FullName, $FromDate, $ToDate, $ConvertETW, $true) -AsJob -PassThru -Activity 'Collect Network Traces'

            # collect the sdndiagnostics etl files if IncludeLogs was provided
            if ($IncludeLogs) {
                $commonConfig = Get-SdnModuleConfiguration -Role:Common

                # check to see if we are using local or network share for the logs
                if (!$diagLogNetShare) {
                    [String]$diagLogDir = $commonConfig.DefaultLogDirectory

                    "Collect diagnostics logs for {0} nodes: {1}" -f $group.Name, ($dataNodes -join ', ') | Trace-Output
                    $outputDir = Join-Path -Path $tempDirectory.FullName -ChildPath 'SdnDiagnosticLogs'
                    Invoke-PSRemoteCommand -ComputerName $dataNodes -Credential $Credential -ScriptBlock $collectLogSB `
                    -ArgumentList @($diagLogDir, $outputDir, $FromDate, $ToDate, $ConvertETW) -AsJob -PassThru -Activity 'Get Diagnostic Log Files'

                    # collect the service fabric logs for the network controller
                    if ($group.Name -ieq 'NetworkController') {
                        $ncConfig = Get-SdnModuleConfiguration -Role:NetworkController
                        [string[]]$sfLogDir = $ncConfig.Properties.CommonPaths.serviceFabricLogDirectory

                        "Collect service fabric logs for {0} nodes: {1}" -f $group.Name, ($dataNodes -join ', ') | Trace-Output
                        $outputDir = Join-Path -Path $tempDirectory.FullName -ChildPath 'ServiceFabricLogs'
                        Invoke-PSRemoteCommand -ComputerName $dataNodes -Credential $Credential -ScriptBlock $collectLogSB `
                        -ArgumentList @($sfLogDir, $outputDir, $FromDate, $ToDate) -AsJob -PassThru -Activity 'Get Service Fabric Logs'
                    }

                    # if the role is a server, collect the audit logs if they are available
                    if ($group.Name -ieq 'Server') {
                        Get-SdnAuditLog -NcUri $sdnFabricDetails.NcUrl -NcRestCredential $NcRestCredential -OutputDirectory "$($OutputDirectory.FullName)\AuditLogs" `
                        -ComputerName $dataNodes -Credential $Credential
                    }
                }

                # if the role is network controller and we are using a network share
                # need to update variable to include the network controller nodes
                # so we can add these supplmental folders to the collection
                if ($group.Name -ieq 'NetworkController') {
                    $ncNodeFolders += $dataNodes
                }

                # collect the event logs specific to the role
                "Collect event logs for {0} nodes: {1}" -f $group.Name, ($dataNodes -join ', ') | Trace-Output

                # because we may have a 'Common' role that is being collected, we need to account for that
                # and ensure that we are collecting the appropriate event logs
                switch ( $group.Name ) {
                    'Common' { $roleArray = @(); $roleArray += $group.Name }
                    default { $roleArray = @(); $roleArray += $group.Name; $roleArray += 'Common' }
                }

                Invoke-PSRemoteCommand -ComputerName $dataNodes -Credential $Credential -ScriptBlock {
                    param([Parameter(Position = 0)][String]$OutputDirectory, [Parameter(Position =1)][String[]]$Role, [Parameter(Position =2)][DateTime]$FromDate, [Parameter(Position = 3)][DateTime]$ToDate)
                    Get-SdnEventLog -OutputDirectory $OutputDirectory -Role $Role -FromDate $FromDate -ToDate $ToDate
                } -ArgumentList @($tempDirectory.FullName, $roleArray, $FromDate, $ToDate) -AsJob -PassThru -Activity "Get $($group.Name) Event Logs"
            }
        }

        if ($diagLogNetShare -and $IncludeLogs) {
            $isNetShareMapped = New-SdnDiagNetworkMappedShare -NetworkSharePath $diagLogNetShare -Credential $Credential
            if ($isNetShareMapped) {
                $outputDir = Join-Path -Path $OutputDirectory.FullName -ChildPath 'NetShare_SdnDiagnosticLogs'

                # create an array of names that we will use to filter the logs
                # this ensures that we will only pick up the logs from the nodes that we are collecting from
                $filterArray = @()
                $dataCollectionNodes.Name | ForEach-Object {
                    $filterArray += (Get-ComputerNameFQDNandNetBIOS -ComputerName $_).ComputerNameNetBIOS
                }
                $filterArray = $filterArray | Sort-Object -Unique

                # create an array of folders to collect the logs from leveraging the common configuration
                $logDir = @()
                $commonConfig.DefaultLogFolders | ForEach-Object {
                    $logDir += Join-Path -Path $diagLogNetShare -ChildPath $_
                }
                $ncNodeFolders | ForEach-Object {
                    $ncNetBiosName = (Get-ComputerNameFQDNandNetBIOS -ComputerName $_).ComputerNameNetBIOS
                    $logDir += Join-Path -Path $diagLogNetShare -ChildPath $ncNetBiosName
                }
                $logDir = $logDir | Sort-Object -Unique

                # create parameters for the Get-SdnDiagnosticLogFile function
                $netDiagLogShareParams = @{
                    LogDir           = $logDir
                    OutputDirectory  = $outputDir
                    FromDate         = $FromDate
                    ToDate           = $ToDate
                    FolderNameFilter = $filterArray
                }

                Get-SdnDiagnosticLogFile @netDiagLogShareParams
            }
        }

        if ($IncludeNetView) {
            "Collect Get-NetView logs for {0}" -f ($filteredDataCollectionNodes -join ', ') | Trace-Output
            $null = Invoke-PSRemoteCommand -ComputerName $filteredDataCollectionNodes -Credential $Credential -ScriptBlock {
                param([Parameter(Position = 0)][String]$OutputDirectory)
                Invoke-SdnGetNetView -OutputDirectory $OutputDirectory `
                    -SkipAdminCheck `
                    -SkipNetshTrace `
                    -SkipVM `
                    -SkipCounters
            } -ArgumentList @($tempDirectory.FullName) -AsJob -PassThru -Activity 'Invoke Get-NetView'
        }

        foreach ($node in $filteredDataCollectionNodes) {
            [System.IO.FileInfo]$formattedDirectoryName = Join-Path -Path $OutputDirectory.FullName -ChildPath $node.ToLower()
            Copy-FileFromRemoteComputer -Path $tempDirectory.FullName -Destination $formattedDirectoryName.FullName -ComputerName $node -Credential $Credential -Recurse -Force
            Copy-FileFromRemoteComputer -Path (Get-TraceOutputFile) -Destination $formattedDirectoryName.FullName -ComputerName $node -Credential $Credential -Force
        }

        $dataCollectionObject.TotalSize = (Get-FolderSize -Path $OutputDirectory.FullName -Total)
        $dataCollectionObject.OutputDirectory = $OutputDirectory.FullName
        $dataCollectionObject.Role = $groupedObjectsByRole.Name
        $dataCollectionObject.Result = 'Success'
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
        $dataCollectionObject.Result = 'Failed'
    }
    finally {
        $stopWatch.Stop()
        $dataCollectionObject.DurationInMinutes = $stopWatch.Elapsed.TotalMinutes

        try {
            "Performing post operations and cleanup of {0} across the SDN fabric" -f $tempDirectory.FullName | Trace-Output

            # check for any failed PS remoting jobs and copy them to data collection
            if (Test-Path -Path "$(Get-WorkingDirectory)\PSRemoteJob_Failures") {
                Copy-Item -Path "$(Get-WorkingDirectory)\PSRemoteJob_Failures" -Destination $formattedDirectoryName.FullName -Recurse
            }

            if ($filteredDataCollectionNodes) {
                Clear-SdnWorkingDirectory -Path $tempDirectory.FullName -Recurse -ComputerName $filteredDataCollectionNodes -Credential $Credential
            }

            # remove any completed or failed jobs
            Remove-SdnDiagnosticJob -State @('Completed', 'Failed')
        }
        catch {
            $_ | Trace-Exception
            Write-Error -Message "An error occurred during cleanup of the SDN fabric." -Exception $_.Exception
            $dataCollectionObject.Result = 'Failed'
        }
    }

    $dataCollectionObject | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'SdnDataCollection_Summary' -FileType json -Depth 4 -ErrorAction Continue
    Copy-Item -Path (Get-TraceOutputFile) -Destination $OutputDirectory.FullName -Force -ErrorAction Continue

    # we will return the object to the caller regardless if the data collection was successful or not
    $msg = "Sdn Data Collection completed with status of {0}" -f $dataCollectionObject.Result
    switch ($dataCollectionObject.Result) {
        'Success' {
            $msg | Trace-Output
        }
        'Failed' {
            $msg | Trace-Output -Level:Error
        }
    }

    return $dataCollectionObject
}
