# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Start-SdnDataCollection {

    <#
    .SYNOPSIS
        Automated data collection script to pull the current configuration state in conjuction with diagnostic logs and other data points used for debugging.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operates.
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
    .EXAMPLE
        PS> Start-SdnDataCollection -NetworkController 'Contoso-NC01' -Role Gateway,NetworkController,Server,SoftwareLoadBalancer
    .EXAMPLE
        PS> Start-SdnDataCollection -NetworkController 'Contoso-NC01' -Role Gateway,NetworkController,Server,SoftwareLoadBalancer -IncludeLogs
    .EXAMPLE
        PS> Start-SdnDataCollection -NetworkController 'Contoso-NC01' -Role Gateway,Server,SoftwareLoadBalancer -IncludeLogs -FromDate (Get-Date).AddHours(-1) -Credential (Get-Credential)
    .EXAMPLE
        PS> Start-SdnDataCollection -NetworkController 'Contoso-NC01' -Role SoftwareLoadBalancer -IncludeLogs -IncludeNetView
    #>

    [CmdletBinding(DefaultParameterSetName = 'Role')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Computer')]
        [System.String]$NetworkController,

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
        [Int]$Limit = 16
    )

    try {
        [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath (Get-FormattedDateTimeUTC)
        [System.IO.FileInfo]$workingDirectory = (Get-WorkingDirectory)
        [System.IO.FileInfo]$tempDirectory = "$(Get-WorkingDirectory)\Temp"

        $dataCollectionNodes = @()
        $filteredDataCollectionNodes = @()

        # setup the directory location where files will be saved to
        "Starting SDN Data Collection" | Trace-Output

        if (-NOT (Initialize-DataCollection -FilePath $OutputDirectory.FullName -MinimumGB 10)) {
            throw New-Object System.Exception("Unable to initialize environment for data collection")
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
                $keyLookup= @('Gateway','NetworkController','Server','SoftwareLoadBalancer')
                foreach ($value in $ComputerName) {
                    foreach ($key in $sdnFabricDetails.Keys) {
                        if ($key -iin $keyLookup) {
                            "Scanning {0} for {1}" -f $key, $value | Trace-Output -Level:Verbose
                            if ($sdnFabricDetails[$key.ToString()].Contains($value)) {
                                $object = [PSCustomObject]@{
                                    Role = $key
                                    Name = $value
                                }

                                "Node {0} with role {1} added for data collection" -f $object.Name, $object.Role | Trace-Output
                                $dataCollectionNodes += $object
                            }
                        }
                    }
                }
            }
        }

        if ($null -eq $dataCollectionNodes) {
            throw New-Object System.NullReferenceException("No data nodes identified")
        }

        $dataCollectionNodes = $dataCollectionNodes | Sort-Object -Property Name -Unique
        $groupedObjectsByRole = $dataCollectionNodes | Group-Object -Property Role
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
            Invoke-PSRemoteCommand -ComputerName $dataNodes -ScriptBlock {
                Clear-SdnWorkingDirectory -Path $using:tempDirectory.FullName -Force -Recurse
            } -Credential $Credential -AsJob -PassThru -Activity 'Clear-SdnTempWorkingDirectory'

            # add the data nodes to new variable, to ensure that we pick up the log files specifically from these nodes
            # to account for if filtering was applied
            $filteredDataCollectionNodes += $dataNodes

            "Collect configuration state details for {0} nodes: {1}" -f $group.Name, ($dataNodes -join ', ') | Trace-Output
            switch ($group.Name) {
                'Gateway' {
                    Invoke-PSRemoteCommand -ComputerName $dataNodes -ScriptBlock {
                        Get-SdnGatewayConfigurationState -OutputDirectory $using:tempDirectory.FullName
                    } -Credential $Credential -AsJob -PassThru -Activity 'Get-SdnGatewayConfigurationState'
                }

                'NetworkController' {
                    Invoke-PSRemoteCommand -ComputerName $dataNodes -ScriptBlock {
                        Get-SdnNetworkControllerConfigurationState -OutputDirectory $using:tempDirectory.FullName
                    } -Credential $Credential -AsJob -PassThru -Activity 'Get-SdnNetworkControllerConfigurationState'

                    Get-SdnApiResource -NcUri $sdnFabricDetails.NcUrl -OutputDirectory $OutputDirectory.FullName -Credential $NcRestCredential
                    Get-SdnNetworkControllerState -NetworkController $NetworkController -OutputDirectory $OutputDirectory.FullName `
                        -Credential $Credential -NcRestCredential $NcRestCredential
                    Get-SdnNetworkControllerClusterInfo -NetworkController $NetworkController -OutputDirectory $OutputDirectory.FullName `
                        -Credential $Credential
                }

                'Server' {
                    Invoke-PSRemoteCommand -ComputerName $dataNodes -ScriptBlock {
                        Get-SdnServerConfigurationState -OutputDirectory $using:tempDirectory.FullName
                    } -Credential $Credential -AsJob -PassThru -Activity 'Get-SdnServerConfigurationState'

                    Get-SdnProviderAddress -ComputerName $dataNodes -Credential $Credential -AsJob -PassThru -Timeout 600 `
                    | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnProviderAddress' -FileType csv

                    Get-SdnVfpVmSwitchPort -ComputerName $dataNodes -Credential $Credential -AsJob -PassThru -Timeout 600 `
                    | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnVfpVmSwitchPort' -FileType csv

                    Get-SdnVMNetworkAdapter -ComputerName $dataNodes -Credential $Credential -AsJob -PassThru -Timeout 900 `
                    | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnVMNetworkAdapter' -FileType csv
                }

                'SoftwareLoadBalancer' {
                    Invoke-PSRemoteCommand -ComputerName $dataNodes -ScriptBlock {
                        Get-SdnSlbMuxConfigurationState -OutputDirectory $using:tempDirectory.FullName
                    } -Credential $Credential -AsJob -PassThru -Activity 'Get-SdnSlbMuxConfigurationState'

                    $slbStateInfo = Get-SdnSlbStateInformation -NcUri $sdnFabricDetails.NcUrl -Credential $NcRestCredential
                    $slbStateInfo | ConvertTo-Json -Depth 100 | Out-File "$($OutputDirectory.FullName)\SlbState.Json"
                }
            }

            # check to see if any network traces were captured on the data nodes previously
            "Checking for any previous network traces and moving them into temp directory" | Trace-Output
            Invoke-PSRemoteCommand -ComputerName $dataNodes -ScriptBlock {
                [System.IO.FileInfo]$networkTraceDir = "$($using:workingDirectory)\NetworkTraces"
                if (Test-Path -Path $networkTraceDir.FullName -PathType Container) {
                    try {
                        Move-Item -Path "$($using:workingDirectory.FullName)\NetworkTraces" -Destination $using:tempDirectory.FullName -ErrorAction Stop
                    }
                    catch {
                        "Unable to move {0} to {1}`n`t{2}" -f $networkTraceDir.FullName, $using:tempDirectory.FullName, $_.Exception | Write-Warning
                    }
                }
            }

            # collect the sdndiagnostics etl files if IncludeLogs was provided
            if ($IncludeLogs) {
                if ($group.Name -ieq 'NetworkController') {
                    "Collect service fabric logs for {0} nodes: {1}" -f $group.Name, ($dataNodes -join ', ') | Trace-Output
                    Invoke-PSRemoteCommand -ComputerName $dataNodes -ScriptBlock {
                        Get-SdnServiceFabricLog -OutputDirectory $using:tempDirectory.FullName -FromDate $using:FromDate
                    } -Credential $Credential -AsJob -PassThru -Activity 'Get-SdnServiceFabricLog'
                }

                "Collect diagnostics logs for {0} nodes: {1}" -f $group.Name, ($dataNodes -join ', ') | Trace-Output
                Invoke-PSRemoteCommand -ComputerName $dataNodes -ScriptBlock {
                    Get-SdnDiagnosticLog -OutputDirectory $using:tempDirectory.FullName -FromDate $using:FromDate
                } -Credential $Credential -AsJob -PassThru -Activity 'Get-SdnDiagnosticLog'

                "Collect event logs for {0} nodes: {1}" -f $group.Name, ($dataNodes -join ', ') | Trace-Output
                Invoke-PSRemoteCommand -ComputerName $dataNodes -ScriptBlock {
                    Get-SdnEventLog -Role $using:group.Name -OutputDirectory $using:tempDirectory.FullName -FromDate $using:FromDate
                } -Credential $Credential -AsJob -PassThru -Activity 'Get-SdnEventLog'
            }
        }

        if ($IncludeNetView) {
            "Collect Get-NetView logs for {0}" -f ($filteredDataCollectionNodes -join ', ') | Trace-Output
            $null = Invoke-PSRemoteCommand -ComputerName $filteredDataCollectionNodes -ScriptBlock {
                Invoke-SdnGetNetView -OutputDirectory $using:tempDirectory.FullName `
                    -SkipAdminCheck `
                    -SkipNetshTrace `
                    -SkipVM `
                    -SkipCounters
            } -Credential $Credential -AsJob -PassThru -Activity 'Invoke-SdnGetNetView'
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
        Invoke-PSRemoteCommand -ComputerName $filteredDataCollectionNodes -ScriptBlock {
            Clear-SdnWorkingDirectory -Path $using:tempDirectory.FullName -Force -Recurse
        } -Credential $Credential -AsJob -PassThru -Activity 'Clear-SdnTempWorkingDirectory'

        "Data collection completed" | Trace-Output
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
