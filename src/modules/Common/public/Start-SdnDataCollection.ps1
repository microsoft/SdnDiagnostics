# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Start-SdnDataCollection {

    <#
    .SYNOPSIS
        Automated network diagnostics and data collection/tracing script.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .PARAMETER DataCollectionType
        Optional parameter that allows the user to define if they want to collect either Configuration, Logs or None. Default is Logs.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding(DefaultParameterSetName = 'Role')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Computer')]
        [System.String]$NetworkController,

        [Parameter(Mandatory = $true, ParameterSetName = 'Role')]
        [SdnRoles[]]$Role,

        [Parameter(Mandatory = $true, ParameterSetName = 'Computer')]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Computer')]
        [System.IO.FileInfo]$OutputDirectory,

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

        [Parameter(Mandatory = $false, ParameterSetName = 'Computer')]
        [Int]$Limit = 16
    )

    try {
        [System.IO.FileInfo]$tempDirectory = "C:\Temp\CSS_SDN"
        $dataCollectionNodes = @()
        $filteredDataCollectionNodes = @()

        # setup the directory location where files will be saved to
        "Starting SDN Data Collection" | Trace-Output
        if ($null -eq $OutputDirectory) {
            [System.IO.FileInfo]$OutputDirectory = (Get-WorkingDirectory)
        }

        [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath (Get-FormattedDateTimeUTC)
        if (-NOT (Test-Path -Path $OutputDirectory.FullName -PathType Container)) {
            $null = New-Item -Path $OutputDirectory.FullName -ItemType Directory -Force
        }

        "Results will be saved to {0}" -f $OutputDirectory.FullName | Trace-Output

        # generate a mapping of the environment
        $sdnFabricDetails = Get-SdnInfrastructureInfo -NetworkController $NetworkController -Credential $Credential -NcRestCredential $NcRestCredential
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
                foreach ($value in $ComputerName) {
                    $roleName = $sdnFabricDetails.Name | Where-Object {$_.Value -icontains $value}

                    $object = [PSCustomObject]@{
                        Role = $roleName
                        Name = $value
                    }

                    $dataCollectionNodes += $object
                }
            }
        }

        # clean up the data collection nodes using -Unique parameter, which is not case sensitive and will ensure no duplicates
        $dataCollectionNodes = $dataCollectionNodes | Sort-Object -Property Name -Unique
        $groupedObjectsByRole = $dataCollectionNodes | Group-Object -Property Role

        # The default location to save data on remote nodes.
        "Cleaning up {0} for temp staging of files and logs" -f $tempDirectory | Trace-Output
        $null = Invoke-PSRemoteCommand -ComputerName $dataCollectionNodes.Name -ScriptBlock {
            if (Test-Path -Path $using:tempDirectory.FullName -PathType Container) {
                Remove-Item -Path "$($using:tempDirectory.FullName)\*" -Recurse -Force
            }
        }

        foreach ($group in $groupedObjectsByRole) {
            if($PSCmdlet.ParameterSetName -eq 'Role'){
                $dataNodes = $group.Group.Name | Select-Object -First $Limit
            }
            else {
                $dataNodes = $group.Group.Name
            }

            # add the data nodes to new variable, to ensure that we pick up the log files specifically from these nodes
            # to account for if filtering was applied
            $filteredDataCollectionNodes += $dataNodes

            "Collecting configuration state details for {0} nodes: {1}" -f $group.Name, ($dataNodes -join ', ') | Trace-Output
            switch ($group.Name) {
                'Gateway' {
                    Invoke-PSRemoteCommand -ComputerName $dataNodes -ScriptBlock {
                        Get-SdnGatewayConfigurationState -OutputDirectory $using:tempDirectory.FullName
                    } -AsJob -PassThru
                }

                'NetworkController' {
                    Invoke-PSRemoteCommand -ComputerName $dataNodes -ScriptBlock {
                        Get-SdnNetworkControllerConfigurationState -OutputDirectory $using:tempDirectory.FullName
                    }

                    Get-SdnApiResource -NcUri $sdnFabricDetails.NcUrl -OutputDirectory $OutputDirectory.FullName -Credential $NcRestCredential
                    Get-SdnNetworkControllerState -NetworkController $NetworkController -OutputDirectory $OutputDirectory.FullName `
                        -Credential $Credential -NcRestCredential $NcRestCredential

                }

                'Server' {
                    Invoke-PSRemoteCommand -ComputerName $dataNodes -ScriptBlock {
                        Get-SdnServerConfigurationState -OutputDirectory $using:tempDirectory.FullName
                    } -AsJob -PassThru

                    Get-SdnProviderAddress -ComputerName $dataNodes -AsJob -PassThru -Timeout 600 `
                    | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnProviderAddress' -FileType csv

                    Get-SdnVfpVmSwitchPort -ComputerName $dataNodes -AsJob -PassThru -Timeout 600 `
                    | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnVfpVmSwitchPort' -FileType csv

                    Get-SdnVMNetworkAdapter -ComputerName $dataNodes -AsJob -PassThru -Timeout 900 `
                    | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnVMNetworkAdapter' -FileType csv
                }

                'SoftwareLoadBalancer' {
                    Invoke-PSRemoteCommand -ComputerName $dataNodes -ScriptBlock {
                        Get-SdnSlbMuxConfigurationState -OutputDirectory $using:tempDirectory.FullName
                    } -AsJob -PassThru

                    $slbStateInfo = Get-SdnSlbStateInformation -NcUri $sdnFabricDetails.NcUrl -Credential $NcRestCredential
                    $slbStateInfo | ConvertTo-Json -Depth 100 | Out-File "$($OutputDirectory.FullName)\SlbState.Json"
                }
            }

            # collect the sdndiagnostics etl files if IncludeLogs was provided
            if ($IncludeLogs) {
                if ($group.Name -ieq 'NetworkController') {
                    "Collecting service fabric logs for {0} nodes: {1}" -f $group.Name, ($dataNodes -join ', ') | Trace-Output
                    Invoke-PSRemoteCommand -ComputerName $dataNodes -ScriptBlock {
                        Get-SdnServiceFabricLog -OutputDirectory $using:tempDirectory.FullName -FromDate $using:FromDate
                    } -AsJob -PassThru
                }

                "Collecting diagnostics logs for {0} nodes: {1}" -f $group.Name, ($dataNodes -join ', ') | Trace-Output
                Invoke-PSRemoteCommand -ComputerName $dataNodes -ScriptBlock {
                    Get-SdnDiagnosticLog -OutputDirectory $using:tempDirectory.FullName -FromDate $using:FromDate
                } -AsJob -PassThru
            }
        }

        if ($IncludeNetView) {
            "Collecting Get-NetView logs for {0}" -f ($dataNodes -join ', ') | Trace-Output
            $null = Invoke-PSRemoteCommand -ComputerName $filteredDataCollectionNodes -ScriptBlock {
                Invoke-SdnGetNetView -OutputDirectory $using:tempDirectory.FullName `
                    -SkipAdminCheck `
                    -SkipNetshTrace `
                    -SkipVM `
                    -SkipCounters
            } -AsJob -PassThru
        }

        foreach ($node in $filteredDataCollectionNodes) {
            [System.IO.FileInfo]$formattedDirectoryName = Join-Path -Path $OutputDirectory.FullName -ChildPath $node.ToLower()
            Copy-FileFromRemoteComputer -Path $tempDirectory.FullName -Destination $formattedDirectoryName.FullName -ComputerName $node -Recurse -Force
        }

        "Data collection completed" | Trace-Output
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
