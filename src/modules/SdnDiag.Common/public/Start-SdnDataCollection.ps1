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
        Optional parameter that allows you to control how many hours worth of logs to retrieve from the system for the roles identified. If ommitted, defaults to 4 hours.
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
        PS> Start-SdnDataCollection -NetworkController 'Contoso-NC01' -Role LoadBalancerMux -IncludeLogs -IncludeNetView
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
        [SdnRoles[]]$Role,

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

    try {
        if (-NOT ($PSBoundParameters.ContainsKey('NetworkController'))) {
            $config = Get-SdnModuleConfiguration -Role 'NetworkController'
            $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
            if (-NOT ($confirmFeatures)) {
                "The current machine is not a NetworkController, run this on NetworkController or use -NetworkController parameter to specify one" | Trace-Output -Level:Warning
                return # don't throw exception, since this is a controlled scenario and we do not need stack exception tracing
            }
        }

        [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath (Get-FormattedDateTimeUTC)
        [System.IO.FileInfo]$workingDirectory = (Get-WorkingDirectory)
        [System.IO.FileInfo]$tempDirectory = "$(Get-WorkingDirectory)\Temp"

        $dataCollectionNodes = @()
        $filteredDataCollectionNodes = @()

        # setup the directory location where files will be saved to
        "Starting SDN Data Collection" | Trace-Output

        if ($IncludeLogs) {
            $minGB = 10
        }
        else {
            $minGB = 5
        }

        if (-NOT (Initialize-DataCollection -FilePath $OutputDirectory.FullName -MinimumGB $minGB)) {
            "Unable to initialize environment for data collection" | Trace-Output -Level:Exception
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

        switch ($PSCmdlet.ParameterSetName) {
            'Role' {
                foreach ($value in $Role) {
                    foreach ($node in $sdnFabricDetails[$value.ToString()]) {
                        $object = [PSCustomObject]@{
                            Role = $value
                            Name = $node
                        }

                        "Node {0} with role {1} added for data collection" -f $object.Name, $object.Role | Trace-Output
                        $dataCollectionNodes += $object
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

                        "Node {0} with role {1} added for data collection" -f $object.Name, $object.Role | Trace-Output
                        $dataCollectionNodes += $object
                    }
                }
            }
        }

        if ($null -eq $dataCollectionNodes) {
            throw New-Object System.NullReferenceException("No data nodes identified")
        }

        $dataCollectionNodes = $dataCollectionNodes | Sort-Object -Property Name -Unique
        $groupedObjectsByRole = $dataCollectionNodes | Group-Object -Property Role

        # ensure SdnDiagnostics installed across the data nodes and versions are the same
        Install-SdnDiagnostics -ComputerName $dataCollectionNodes.Name -ErrorAction Stop

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

            $slbStateInfo = Get-SdnSlbStateInformation -NcUri $sdnFabricDetails.NcUrl -Credential $NcRestCredential
            $slbStateInfo | ConvertTo-Json -Depth 100 | Out-File "$($OutputDirectory.FullName)\SlbState.Json"
            Invoke-SdnResourceDump -NcUri $sdnFabricDetails.NcUrl -OutputDirectory $OutputDirectory.FullName -Credential $NcRestCredential
            Get-SdnNetworkControllerState -NetworkController $NetworkController -OutputDirectory $OutputDirectory.FullName -Credential $Credential -NcRestCredential $NcRestCredential
            Get-SdnNetworkControllerClusterInfo -NetworkController $NetworkController -OutputDirectory $OutputDirectory.FullName -Credential $Credential

            "Collect configuration state details for {0} nodes: {1}" -f $group.Name, ($dataNodes -join ', ') | Trace-Output
            switch ($group.Name) {
                'Gateway' {
                    Invoke-PSRemoteCommand -ComputerName $dataNodes -Credential $Credential -ScriptBlock {
                        param([Parameter(Position = 0)][String]$OutputDirectory)
                        Get-SdnGatewayConfigurationState -OutputDirectory $OutputDirectory
                    } -ArgumentList $tempDirectory.FullName -AsJob -PassThru -Activity 'Get-SdnGatewayConfigurationState'
                }

                'NetworkController' {
                    Invoke-PSRemoteCommand -ComputerName $dataNodes -Credential $Credential -ScriptBlock {
                        param([Parameter(Position = 0)][String]$OutputDirectory)
                        Get-SdnNetworkControllerConfigurationState -OutputDirectory $OutputDirectory
                    } -ArgumentList $tempDirectory.FullName -AsJob -PassThru -Activity 'Get-SdnNetworkControllerConfigurationState'
                }

                'Server' {
                    Invoke-PSRemoteCommand -ComputerName $dataNodes -Credential $Credential -ScriptBlock {
                        param([Parameter(Position = 0)][String]$OutputDirectory)
                        Get-SdnServerConfigurationState -OutputDirectory $OutputDirectory
                    } -ArgumentList $tempDirectory.FullName -AsJob -PassThru -Activity 'Get-SdnServerConfigurationState'

                    Get-SdnProviderAddress -ComputerName $dataNodes -Credential $Credential `
                    | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnProviderAddress' -FileType csv

                    Get-SdnVfpVmSwitchPort -ComputerName $dataNodes -Credential $Credential `
                    | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnVfpVmSwitchPort' -FileType csv

                    Get-SdnVMNetworkAdapter -ComputerName $dataNodes -Credential $Credential -AsJob -PassThru -Timeout 900 `
                    | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnVMNetworkAdapter' -FileType csv
                }

                'LoadBalancerMux' {
                    Invoke-PSRemoteCommand -ComputerName $dataNodes -Credential $Credential -ScriptBlock {
                        param([Parameter(Position = 0)][String]$OutputDirectory)
                        Get-SdnSlbMuxConfigurationState -OutputDirectory $OutputDirectory
                    } -ArgumentList $tempDirectory.FullName -AsJob -PassThru -Activity 'Get-SdnSlbMuxConfigurationState'
                }
            }

            # check to see if any network traces were captured on the data nodes previously
            "Checking for any previous network traces and moving them into {0}" -f $tempDirectory.FullName | Trace-Output
            Invoke-PSRemoteCommand -ComputerName $dataNodes -Credential $Credential -ScriptBlock {
                param ([Parameter(Position = 0)][String]$NetworkTraceDir, [Parameter(Position = 1)][String]$TempDirectory, [Parameter(Position = 2)]$ConvertETW)
                if (Test-Path -Path $NetworkTraceDir -PathType Container) {

                    # convert the most recent etl trace file into human readable format without requirement of additional parsing tools
                    if ($ConvertETW) {
                        $convertFile = Get-Item -Path "$NetworkTraceDir\*" -Include '*.etl' | Sort-Object -Property LastWriteTime | Select-Object -Last 1
                        if ($convertFile) {
                            $null = Convert-SdnEtwTraceToTxt -FileName $convertFile.FullName -Overwrite 'Yes'
                        }
                    }

                    # move the entire directory
                    try {
                        Move-Item -Path $NetworkTraceDir -Destination $TempDirectory -Force -ErrorAction Stop
                    }
                    catch {
                        "Unable to move {0} to {1}`n`t{2}" -f $NetworkTraceDir, $TempDirectory, $_.Exception | Write-Warning
                    }
                }
            } -ArgumentList @("$($workingDirectory.FullName)\NetworkTraces", $tempDirectory.FullName, $ConvertETW)

            # collect the sdndiagnostics etl files if IncludeLogs was provided
            if ($IncludeLogs) {
                if ($group.Name -ieq 'NetworkController') {
                    "Collect service fabric logs for {0} nodes: {1}" -f $group.Name, ($dataNodes -join ', ') | Trace-Output
                    Invoke-PSRemoteCommand -ComputerName $dataNodes -Credential $Credential -ScriptBlock {
                        param([Parameter(Position = 0)][String]$OutputDirectory, [Parameter(Position = 1)][DateTime]$FromDate)
                        Get-SdnServiceFabricLog -OutputDirectory $OutputDirectory -FromDate $FromDate
                    } -ArgumentList @($tempDirectory.FullName, $FromDate) -AsJob -PassThru -Activity 'Get-SdnServiceFabricLog'
                }

                if ($group.Name -ieq 'Server') {
                    Get-SdnAuditLog -NcUri $sdnFabricDetails.NcUrl -NcRestCredential $NcRestCredential -OutputDirectory "$($OutputDirectory.FullName)\AuditLogs" `
                    -ComputerName $dataNodes -Credential $Credential
                }

                "Collect diagnostics logs for {0} nodes: {1}" -f $group.Name, ($dataNodes -join ', ') | Trace-Output
                Invoke-PSRemoteCommand -ComputerName $dataNodes -Credential $Credential -ScriptBlock {
                    param([Parameter(Position = 0)][String]$OutputDirectory, [Parameter(Position = 1)][DateTime]$FromDate, [Parameter(Position = 2)]$ConvertETW)
                    Get-SdnDiagnosticLog -OutputDirectory $OutputDirectory -FromDate $FromDate -ConvertETW $ConvertETW
                } -ArgumentList @($tempDirectory.FullName, $FromDate, $ConvertETW) -AsJob -PassThru -Activity 'Get-SdnDiagnosticLog'

                "Collect event logs for {0} nodes: {1}" -f $group.Name, ($dataNodes -join ', ') | Trace-Output
                Invoke-PSRemoteCommand -ComputerName $dataNodes -Credential $Credential -ScriptBlock {
                    param([Parameter(Position = 0)][String]$OutputDirectory, [Parameter(Position =1)][String]$Role, [Parameter(Position =2)][DateTime]$FromDate)
                    Get-SdnEventLog -OutputDirectory $OutputDirectory -Role $Role -FromDate $FromDate
                } -ArgumentList @($tempDirectory.FullName, $group.Name, $FromDate) -AsJob -PassThru -Activity 'Get-SdnEventLog'
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
            } -ArgumentList @($tempDirectory.FullName) -AsJob -PassThru -Activity 'Invoke-SdnGetNetView'
        }

        foreach ($node in $filteredDataCollectionNodes) {
            [System.IO.FileInfo]$formattedDirectoryName = Join-Path -Path $OutputDirectory.FullName -ChildPath $node.ToLower()
            Copy-FileFromRemoteComputer -Path $tempDirectory.FullName -Destination $formattedDirectoryName.FullName -ComputerName $node -Credential $Credential -Recurse -Force
            Copy-FileFromRemoteComputer -Path (Get-TraceOutputFile) -Destination $formattedDirectoryName.FullName -ComputerName $node -Credential $Credential -Force
        }

        # check for any failed PS remoting jobs and copy them to data collection
        if (Test-Path -Path "$(Get-WorkingDirectory)\PSRemoteJob_Failures") {
            Copy-Item -Path "$(Get-WorkingDirectory)\PSRemoteJob_Failures" -Destination $formattedDirectoryName.FullName -Recurse
        }

        "Performing cleanup of {0} directory across {1}" -f $tempDirectory.FullName, ($filteredDataCollectionNodes -join ', ') | Trace-Output
        Clear-SdnWorkingDirectory -Path $tempDirectory.FullName -Recurse -ComputerName $filteredDataCollectionNodes -Credential $Credential

        "Data collection completed" | Trace-Output
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
