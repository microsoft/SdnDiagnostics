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
        [Parameter(Mandatory = $true, ParameterSetName = 'Node')]
        [System.String]$NetworkController,

        [Parameter(Mandatory = $true, ParameterSetName = 'Role')]
        [SdnRoles[]]$Role,

        [Parameter(Mandatory = $true, ParameterSetName = 'Node')]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Node')]
        [System.IO.FileInfo]$OutputDirectory,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Node')]
        [Switch]$IncludeLogs,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Node')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Node')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Node')]
        [Int]$Limit = 16
    )

    try {
        $ncNodes = [System.Collections.Generic.List[Object]]::new()
        $slbNodes = [System.Collections.Generic.List[Object]]::new()
        $serverNodes = [System.Collections.Generic.List[Object]]::new()
        $gatewayNodes = [System.Collections.Generic.List[Object]]::new()
        $dataCollectionNodes = [System.Collections.Generic.List[Object]]::new()
        $filteredDataCollectionNodes = [System.Collections.Generic.List[Object]]::new()
        $dataCollectionRoles = [System.Collections.Generic.List[Object]]::new()

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

                        "Node {0} with Role {1} added for data collection" -f $object.Name, $object.Role | Trace-Output
                        $dataCollectionNodes.Add($object)
                    }
                }
            }

            'Node' {
                foreach ($value in $ComputerName) {
                    $roleName = $sdnFabricDetails.Name | Where-Object {$_.Value -icontains $value}

                    $object = [PSCustomObject]@{
                        Role = $roleName
                        Name = $value
                    }

                    $dataCollectionNodes.Add($object)
                }
            }
        }

        # clean up the data collection nodes using -Unique parameter, which is not case sensitive and will ensure no duplicates
        # once the duplicate objects have been removed, we want to parse each result to add it to variable assignemtn for easier reference
        # later in the script
        $dataCollectionNodes = $dataCollectionNodes | Sort-Object -Property Name -Unique
        $groupedNodes = $dataCollectionNodes | Group-Object Role

        foreach ($object in $groupedNodes) {
            $filteredNodes = $object.Group | Select-Object -First $Limit
            if($object.Count -gt $Limit){
                "{0} contains more than the defined limit of {1}. Applying filtering rules" -f $object.Name, $Limit | Trace-Output -Level:Warning
                $filteredDataCollectionNodes.Add($filteredNodes)
            }

            switch ($object.Name) {
                'Gateway' {
                    $gatewayNodes = $filteredNodes.Name
                }

                'NetworkController' {
                    $ncNodes = $filteredNodes.Name
                }

                'Server' {
                    $serverNodes = $filteredNodes.Name
                }

                'SoftwareLoadBalancer' {
                    $slbNodes = $filteredNodes.Name
                }
            }
        }

        # create a list of roles that need to be targetted, as data collection happens
        # using a combination of role and computer names
        $dataCollectionRoles = $groupedNodes.Name

        # generate configuration state files for the environment
        "Collecting configuration state details for SDN fabric" | Trace-Output
        Get-SdnApiResource -NcUri $sdnFabricDetails.NcUrl -OutputDirectory $OutputDirectory.FullName -Credential $NcRestCredential
        Get-SdnNetworkControllerState -NetworkController $NetworkController -OutputDirectory $OutputDirectory.FullName `
            -Credential $Credential -NcRestCredential $NcRestCredential

        "Will collect logs for role {0}" -f ($dataCollectionRoles -join ",") | Trace-Output

        # The default location to save data on remote nodes.
        $OutputDirectoryOnNodes = "C:\Temp\CSS_SDN"
        Invoke-PSRemoteCommand -ComputerName $dataCollectionNodes.Name -ScriptBlock {
            "[{0}] Cleanup existing files under {1}" -f $(HostName), $using:OutputDirectoryOnNodes | Write-Host
            Get-ChildItem $using:OutputDirectoryOnNodes | Remove-Item -Recurse -Force
        }
        foreach($result in $dataCollectionRoles){
            switch ($result) {
                'Gateway' {
                    "Collecting configuration state details for {0} nodes: {1}" -f $result, ($gatewayNodes -join ', ') | Trace-Output
                    Invoke-PSRemoteCommand -ComputerName $gatewayNodes -ScriptBlock {
                        Get-SdnGatewayConfigurationState -OutputDirectory $using:OutputDirectoryOnNodes
                    }
                }

                'NetworkController' {
                    "Collecting configuration state details for {0} nodes: {1}" -f $result, ($ncNodes -join ', ') | Trace-Output
                    Invoke-PSRemoteCommand -ComputerName $ncNodes -ScriptBlock {
                        Get-SdnNetworkControllerConfigurationState -OutputDirectory $using:OutputDirectoryOnNodes
                    }
                }

                'Server' {
                    "Collecting configuration state details for {0} nodes: {1}" -f $result, ($serverNodes -join ', ') | Trace-Output
                    Invoke-PSRemoteCommand -ComputerName $serverNodes -ScriptBlock {
                        Get-SdnServerConfigurationState -OutputDirectory $using:OutputDirectoryOnNodes
                    }

                    Get-SdnProviderAddress -ComputerName $serverNodes -AsJob -PassThru -Timeout 600 `
                    | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnProviderAddress' -FileType csv

                    Get-SdnVfpVmSwitchPort -ComputerName $serverNodes -AsJob -PassThru -Timeout 600 `
                    | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnVfpVmSwitchPort' -FileType csv

                    Get-SdnVMNetworkAdapter -ComputerName $serverNodes -AsJob -PassThru -Timeout 900 `
                    | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnVMNetworkAdapter' -FileType csv

                }

                'SoftwareLoadBalancer' {
                    "Collecting configuration state details for {0} nodes: {1}" -f $result, ($slbNodes -join ', ') | Trace-Output
                    Invoke-PSRemoteCommand -ComputerName $slbNodes -ScriptBlock {
                        Get-SdnSlbMuxConfigurationState -OutputDirectory $using:OutputDirectoryOnNodes
                    }

                    $slbStateInfo = Get-SdnSlbStateInformation -NcUri $sdnFabricDetails.NcUrl -Credential $NcRestCredential
                    $slbStateInfo | ConvertTo-Json -Depth 100 | Out-File "$($OutputDirectory.FullName)\SlbState.Json"
                }

                default {
                    "Unable to determine role mapping for {0}" -f $result | Trace-Output -Level:Error
                    continue
                }
            }
        }

        foreach($node in $dataCollectionNodes)
        {
            Copy-FileFromRemoteComputer -Path $OutputDirectoryOnNodes -Destination "$OutputDirectory\$($node.name)" -ComputerName $node.name -Recurse -Force
        }

    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}