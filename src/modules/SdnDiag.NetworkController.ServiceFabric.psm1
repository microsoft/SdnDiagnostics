# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. "$PSScriptRoot\..\scripts\SdnDiag.Utilities.ps1"

function Move-SdnServiceFabricReplica {
    <#
    .SYNOPSIS
        Moves the Service Fabric primary replica of a stateful service partition on Network Controller.
    .PARAMETER ApplicationName
        A service fabric application name that exists on the provided ring, such as fabric:/NetworkController.
    .PARAMETER ServiceName
        A service fabric service name that is under the provided ApplicationName on the provided ring, such as fabric:/NetworkController/ApiService.
    .PARAMETER ServiceTypeName
        A service fabric service TypeName, such as VSwitchService.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER NodeName
        Specifies the name of a Service Fabric node. The cmdlet moves the primary replica to the node that you specify.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS > Move-SdnServiceFabricReplica -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -ServiceTypeName 'ApiService'
    #>

    [CmdletBinding(DefaultParameterSetName = 'NamedService')]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [String]$ApplicationName = 'fabric:/NetworkController',

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [String]$ServiceName,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [String]$ServiceTypeName,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String[]]$NetworkController = $global:SdnDiagnostics.InfrastructureInfo.NetworkController,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String]$NodeName,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )
    try {
        if ($PSCmdlet.ParameterSetName -eq 'NamedService') {
            $sfParams = @{
                ServiceName = $ServiceName
                Credential  = $Credential
            }
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'NamedServiceTypeName') {
            $sfParams = @{
                ServiceTypeName = $ServiceTypeName
                Credential      = $Credential
            }
        }

        # add NetworkController to hash table for splatting if defined
        if ($NetworkController) {
            [void]$sfParams.Add('NetworkController', $NetworkController)
        }

        # check to determine how many replicas are part of the partition for the service
        # if we only have a single replica, then generate a warning and stop further processing
        # otherwise locate the primary replica
        $service = Get-SdnServiceFabricService @sfParams -ErrorAction Stop
        $serviceFabricReplicas = Get-SdnServiceFabricReplica @sfParams
        if ($serviceFabricReplicas.Count -lt 3) {
            "Moving Service Fabric replica is only supported when running 3 or more instances of Network Controller" | Trace-Output -Level:Warning
            return
        }

        $replicaBefore = $serviceFabricReplicas | Where-Object { $_.ReplicaRole -ieq 'Primary' }

        # regardless if user defined ServiceName or ServiceTypeName, the $service object returned will include the ServiceName property
        # which we will use to perform the move operation with
        if ($NodeName) {
            $sb = {
                Move-ServiceFabricPrimaryReplica -ServiceName $using:service.ServiceName -NodeName $using:NodeName
            }
        }
        else {
            $sb = {
                Move-ServiceFabricPrimaryReplica -ServiceName $using:service.ServiceName
            }
        }

        # no useful information is returned during the move operation, so we will just null the results that are returned back
        if ($NetworkController) {
            $null = Invoke-SdnServiceFabricCommand -NetworkController $NetworkController -ScriptBlock $sb -Credential $Credential -ErrorAction Stop
        }
        else {
            $null = Invoke-SdnServiceFabricCommand -ScriptBlock $sb -Credential $Credential -ErrorAction Stop
        }

        # update the hash table to now define -Primary switch, which will be used to get the service fabric replica primary
        [void]$sfParams.Add('Primary', $true)
        $replicaAfter = Get-SdnServiceFabricReplica @sfParams
        "Replica for {0} has been moved from {1} to {2}" -f $service.ServiceName, $replicaBefore.NodeName, $replicaAfter.NodeName | Trace-Output
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnServiceFabricApplicationHealth {
    <#
    .SYNOPSIS
        Gets the health of a Service Fabric application from Network Controller.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER ApplicationName
        A service fabric application name that exists on the provided ring, such as fabric:/NetworkController.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnServiceFabricApplicationHealth -NetworkController 'NC01' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String[]]$NetworkController = $global:SdnDiagnostics.InfrastructureInfo.NetworkController,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [String]$ApplicationName = 'fabric:/NetworkController',

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if ($NetworkController) {
            Invoke-SdnServiceFabricCommand -NetworkController $NetworkController -ScriptBlock { Get-ServiceFabricApplicationHealth -ApplicationName $using:ApplicationName } -Credential $Credential
        }
        else {
            Invoke-SdnServiceFabricCommand -ScriptBlock { Get-ServiceFabricApplicationHealth -ApplicationName $using:ApplicationName } -Credential $Credential
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnServiceFabricClusterConfig {
    <#
    .SYNOPSIS
        Gets Service Fabric Cluster Config Properties.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates. Default to local machine.
    .PARAMETER Uri
        The Uri to read properties from ClusterConfiguration, GlobalConfiguration
    .PARAMETER Name
        Property Name to filter the result. If not specified, it will return all properties.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnServiceFabricClusterConfig -NetworkController 'NC01' -Uri "ClusterConfiguration" -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]$NetworkController = $(HostName),

        [Parameter(Mandatory = $true)]
        [ValidateSet('GlobalConfiguration', 'ClusterConfiguration')]
        [String]$Uri,

        [Parameter(Mandatory = $false)]
        [String]$Name,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        Connect-ServiceFabricCluster | Out-Null
        $client = [System.Fabric.FabricClient]::new()
        $result = $null
        $absoluteUri = "fabric:/NetworkController/$Uri"
        $binaryMethod = [System.Fabric.NamedProperty].getmethod("GetValue").MakeGenericMethod([byte[]])
        $stringMethod = [System.Fabric.NamedProperty].getmethod("GetValue").MakeGenericMethod([string])

        $results = [System.Collections.ArrayList]::new()
        do {
            $result = $client.PropertyManager.EnumeratePropertiesAsync($absoluteUri, $true, $result).Result
            $result.GetEnumerator() | ForEach-Object {
                $propertyName = $_.Metadata.PropertyName

                $propertyObj = [PSCustomObject]@{
                    Name  = $propertyName
                    Value = $null
                }
                if ($_.Metadata.TypeId -ieq "string") {
                    $value = $stringMethod.Invoke($_, $null);
                    $propertyObj.Value = $value

                }
                elseif ($_.Metadata.TypeId -ieq "binary") {
                    # only binary value exist is certificate
                    $value = $binaryMethod.Invoke($_, $null);
                    $certObj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($value)
                    $propertyObj.Value = $certObj
                }

                if ($PSBoundParameters.ContainsKey('Name')) {
                    if ($propertyName -ieq $Name) {
                        $results.Add($propertyObj) | Out-Null
                        # Property Name is uniqueue so when name found, return the list
                        return $results
                    }
                }
                else {
                    $results.Add($propertyObj) | Out-Null
                }
            }
        }
        while ($result.HasMoreData)
        return $results
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnServiceFabricClusterHealth {
    <#
    .SYNOPSIS
        Gets health information for a Service Fabric cluster from Network Controller.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnServiceFabricClusterHealth -NetworkController 'NC01' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String[]]$NetworkController = $global:SdnDiagnostics.InfrastructureInfo.NetworkController,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if ($NetworkController) {
            Invoke-SdnServiceFabricCommand -NetworkController $NetworkController -ScriptBlock { Get-ServiceFabricClusterHealth } -Credential $Credential
        }
        else {
            Invoke-SdnServiceFabricCommand -ScriptBlock { Get-ServiceFabricClusterHealth } -Credential $Credential
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnServiceFabricClusterManifest {
    <#
    .SYNOPSIS
        Gets the Service Fabric cluster manifest, including default configurations for reliable services from Network Controller.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnServiceFabricClusterManifest -NetworkController 'NC01'
    .EXAMPLE
        PS> Get-SdnServiceFabricClusterManifest -NetworkController 'NC01' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String[]]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if (-NOT ($PSBoundParameters.ContainsKey('NetworkController'))) {
            $config = Get-SdnRoleConfiguration -Role 'NetworkController'
            $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
            if (-NOT ($confirmFeatures)) {
                "The current machine is not a NetworkController, run this on NetworkController or use -NetworkController parameter to specify one" | Trace-Output -Level:Warning
                return # don't throw exception, since this is a controlled scenario and we do not need stack exception tracing
            }
        }

        # in instances where Service Fabric is down/offline we want to catch any exceptions returned by Invoke-SdnServiceFabricCommand
        # and then fallback to getting the cluster manifest information from the file system directly
        try {
            $clusterManifest = Invoke-SdnServiceFabricCommand -NetworkController $NetworkController -ScriptBlock { Get-ServiceFabricClusterManifest } -Credential $Credential
        }
        catch {
            "Unable to retrieve ClusterManifest directly from Service Fabric. Attempting to retrieve ClusterManifest from file system" | Trace-Output -Level:Warning

            # we want to loop through if multiple NetworkController objects were passed into the cmdlet
            foreach ($obj in $NetworkController) {
                $clusterManifestScript = {
                    $clusterManifestFile = Get-ChildItem -Path "C:\ProgramData\Microsoft\Service Fabric" -Recurse -Depth 2 -Filter "ClusterManifest.current.xml" -ErrorAction SilentlyContinue
                    if ($clusterManifestFile) {
                        $clusterManifest = Get-Content -Path $clusterManifestFile.FullName -ErrorAction SilentlyContinue
                        return $clusterManifest
                    }

                    return $null
                }

                if (Test-ComputerNameIsLocal -ComputerName $obj) {
                    $xmlClusterManifest = Invoke-Command -ScriptBlock $clusterManifestScript
                }
                else {
                    $xmlClusterManifest = Invoke-PSRemoteCommand -ComputerName $obj -Credential $Credential -ScriptBlock $clusterManifestScript
                }

                # once the cluster manifest has been retrieved from the file system break out of the loop
                if ($xmlClusterManifest) {
                    "Successfully retrieved ClusterManifest from {0}" -f $obj | Trace-Output
                    $clusterManifest = $xmlClusterManifest
                    break
                }
            }
        }

        if ($null -eq $clusterManifest) {
            throw New-Object System.NullReferenceException("Unable to retrieve ClusterManifest from Network Controller")
        }

        if ($clusterManifest) {
            # Convert to native Powershell XML
            $xmlClusterManifest = [xml]$clusterManifest

            # Although the strings are encrypted, they should be sanitized anyway
            # Change PrimaryAccountNTLMPasswordSecret and SecondaryAccountNTLMPasswordSecret to removed_for_security_reasons
            (($xmlClusterManifest.ClusterManifest.FabricSettings.Section | Where-Object { $_.Name -eq "FileStoreService" }).Parameter | Where-Object { $_.Name -eq "PrimaryAccountNTLMPasswordSecret" }).Value = "removed_for_security_reasons"
            (($xmlClusterManifest.ClusterManifest.FabricSettings.Section | Where-Object { $_.Name -eq "FileStoreService" }).Parameter | Where-Object { $_.Name -eq "SecondaryAccountNTLMPasswordSecret" }).Value = "removed_for_security_reasons"

            # If we want to keep newlines and indents, but return a string, we need to use the writer class
            # $xmlClusterManifest.OuterXml does not keep the formatting
            $stringWriter = New-Object System.IO.StringWriter
            $writer = New-Object System.Xml.XmlTextwriter($stringWriter)
            $writer.Formatting = [System.XML.Formatting]::Indented

            # Write the manifest to the StringWriter
            $xmlClusterManifest.WriteContentTo($writer)

            # Return the manifest as a string
            return $stringWriter.ToString()
        }

        return $clusterManifest
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnServiceFabricLog {
    <#
    .SYNOPSIS
        Collect the default enabled logs from Service Fabric folder
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .PARAMETER FromDate
        Optional parameter that allows you to control how many hours worth of logs to retrieve from the system for the roles identified. Default is 4 hours.
    .EXAMPLE
        PS> Get-SdnServiceFabricLog -OutputDirectory "C:\Temp\CSS_SDN\SFLogs"
    .EXAMPLE
        PS> Get-SdnServiceFabricLog -OutputDirectory "C:\Temp\CSS_SDN\SFLogs" -FromDate (Get-Date).AddHours(-1)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [System.IO.FileInfo]$OutputDirectory,

        [parameter(Mandatory = $false, Position = 1)]
        [DateTime]$FromDate = (Get-Date).AddHours(-4)
    )

    try {
        $config = Get-SdnRoleConfiguration -Role:NetworkController
        [System.IO.FileInfo]$logDir = $config.properties.commonPaths.serviceFabricLogDirectory
        [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath "ServiceFabricLogs"

        "Collect Service Fabric logs between {0} and {1} UTC" -f $FromDate.ToUniversalTime(), (Get-Date).ToUniversalTime() | Trace-Output

        $logFiles = Get-ChildItem -Path $logDir.FullName -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $FromDate }
        if ($null -eq $logFiles) {
            "No log files found under {0} between {1} and {2} UTC." -f $logDir.FullName, $FromDate.ToUniversalTime(), (Get-Date).ToUniversalTime() | Trace-Output -Level:Warning
            return
        }

        $minimumDiskSpace = [float](Get-FolderSize -FileName $logFiles.FullName -Total).GB * 3.5
        # we want to call the initialize datacollection after we have identify the amount of disk space we will need to create a copy of the logs
        if (-NOT (Initialize-DataCollection -FilePath $OutputDirectory.FullName -MinimumGB $minimumDiskSpace)) {
            throw New-Object System.Exception("Unable to initialize environment for data collection")
        }

        # copy the log files from the default log directory to the output directory
        "Copying {0} files to {1}" -f $logFiles.Count, $OutputDirectory.FullName | Trace-Output -Level:Verbose
        Copy-Item -Path $logFiles.FullName -Destination $OutputDirectory.FullName -Force

        # once we have copied the files to the new location we want to compress them to reduce disk space
        # if confirmed we have a .zip file, then remove the staging folder
        "Compressing results to {0}" -f "$($OutputDirectory.FullName).zip" | Trace-Output -Level:Verbose
        Compress-Archive -Path "$($OutputDirectory.FullName)\*" -Destination $OutputDirectory.FullName -CompressionLevel Optimal -Force
        if (Test-Path -Path "$($OutputDirectory.FullName).zip" -PathType Leaf) {
            Remove-Item -Path $OutputDirectory.FullName -Force -Recurse
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnServiceFabricNode {
    <#
    .SYNOPSIS
        Gets information for all nodes in a Service Fabric cluster for Network Controller.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER NodeName
        Specifies the name of the Service Fabric node whose information is being returned. If not specified, the cmdlet will return information for all the nodes in the cluster.
    .EXAMPLE
        PS> Get-SdnServiceFabricNode -NetworkController 'Prefix-NC01' -Credential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnServiceFabricNode -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -NodeName 'Prefix-NC02'
    .EXAMPLE
        PS> Get-SdnServiceFabricNode -NodeName 'Prefix-NC01'
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String[]]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [System.String]$NodeName

    )

    try {

        if (-NOT ($PSBoundParameters.ContainsKey('NetworkController'))) {
            $config = Get-SdnRoleConfiguration -Role 'NetworkController'
            $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
            if (-NOT ($confirmFeatures)) {
                "The current machine is not a NetworkController, run this on NetworkController or use -NetworkController parameter to specify one" | Trace-Output -Level:Warning
                return # don't throw exception, since this is a controlled scenario and we do not need stack exception tracing
            }
        }

        if ($NodeName) {
            $sb = {
                Get-ServiceFabricNode -NodeName $using:NodeName
            }
        }
        else {
            $sb = {
                Get-ServiceFabricNode
            }
        }

        Invoke-SdnServiceFabricCommand -NetworkController $NetworkController -ScriptBlock $sb -Credential $Credential
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnServiceFabricPartition {
    <#
    .SYNOPSIS
        Gets information about the partitions of a specified Service Fabric partition or service from Network Controller.
    .PARAMETER ApplicationName
        A service fabric application name that exists on the provided ring, such as fabric:/NetworkController.
    .PARAMETER ServiceName
        A service fabric service name that is under the provided ApplicationName on the provided ring, such as fabric:/NetworkController/ApiService.
    .PARAMETER ServiceTypeName
        A service fabric service TypeName, such as VSwitchService.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnServiceFabricPartition -PartitionId 1a7a780e-dbfe-46d3-92fb-76908a95ce54
    .EXAMPLE
        PS> Get-SdnServiceFabricPartition -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -ServiceTypeName 'ApiService'
    .EXAMPLE
        PS> Get-SdnServiceFabricPartition -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -ServiceName 'fabric:/NetworkController/ApiService'
    #>

    [CmdletBinding(DefaultParameterSetName = 'NamedService')]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String]$ApplicationName = 'fabric:/NetworkController',

        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [System.String]$ServiceName,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String]$ServiceTypeName,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'PartitionID')]
        [System.Guid]$PartitionId,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'PartitionID')]
        [System.String[]]$NetworkController = $global:SdnDiagnostics.InfrastructureInfo.NetworkController,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'PartitionID')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        switch ($PSCmdlet.ParameterSetName) {
            'NamedService' {
                $sb = {
                    Get-ServiceFabricApplication -ApplicationName $using:ApplicationName | Get-ServiceFabricService -ServiceName $using:ServiceName | Get-ServiceFabricPartition
                }
            }

            'NamedServiceTypeName' {
                $sb = {
                    Get-ServiceFabricApplication -ApplicationName $using:ApplicationName | Get-ServiceFabricService -ServiceTypeName $using:ServiceTypeName | Get-ServiceFabricPartition
                }
            }

            'PartitionID' {
                $sb = {
                    Get-ServiceFabricPartition -PartitionId $using:PartitionId
                }
            }

            default {
                # no default
            }
        }

        if ($NetworkController) {
            return (Invoke-SdnServiceFabricCommand -NetworkController $NetworkController -ScriptBlock $sb -Credential $Credential)
        }
        else {
            return (Invoke-SdnServiceFabricCommand -ScriptBlock $sb -Credential $Credential)
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnServiceFabricReplica {
    <#
    .SYNOPSIS
        Gets Service Fabric replicas of a partition from Network Controller.
    .PARAMETER ApplicationName
        A service fabric application name that exists on the provided ring, such as fabric:/NetworkController.
    .PARAMETER ServiceName
        A service fabric service name that is under the provided ApplicationName on the provided ring, such as fabric:/NetworkController/ApiService.
    .PARAMETER ServiceTypeName
        A service fabric service TypeName, such as VSwitchService.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnServiceFabricReplica -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -ServiceTypeName 'ApiService'
    .EXAMPLE
        PS> Get-SdnServiceFabricReplica -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -ServiceName 'fabric:/NetworkController/ApiService'
    #>

    [CmdletBinding(DefaultParameterSetName = 'NamedService')]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String]$ApplicationName = 'fabric:/NetworkController',

        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [System.String]$ServiceName,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String]$ServiceTypeName,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String[]]$NetworkController = $global:SdnDiagnostics.InfrastructureInfo.NetworkController,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [Switch]$Primary
    )

    try {
        switch ($PSCmdlet.ParameterSetName) {
            'NamedService' {
                $sb = {
                    Get-ServiceFabricApplication -ApplicationName $using:ApplicationName | Get-ServiceFabricService -ServiceName $using:ServiceName | Get-ServiceFabricPartition | Get-ServiceFabricReplica
                }
            }

            'NamedServiceTypeName' {
                $sb = {
                    Get-ServiceFabricApplication -ApplicationName $using:ApplicationName | Get-ServiceFabricService -ServiceTypeName $using:ServiceTypeName | Get-ServiceFabricPartition | Get-ServiceFabricReplica
                }
            }

            default {
                # no default
            }
        }

        if ($NetworkController) {
            $replica = Invoke-SdnServiceFabricCommand -NetworkController $NetworkController -ScriptBlock $sb -Credential $Credential
        }
        else {
            $replica = Invoke-SdnServiceFabricCommand -ScriptBlock $sb -Credential $Credential
        }

        # as network controller only leverages stateful service fabric services, we will have Primary and ActiveSecondary replicas
        # if the -Primary switch was declared, we only want to return the primary replica for that particular service
        if ($Primary) {
            return ($replica | Where-Object { $_.ReplicaRole -ieq 'Primary' })
        }
        else {
            return $replica
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnServiceFabricService {
    <#
    .SYNOPSIS
        Gets a list of Service Fabric services from Network Controller.
    .PARAMETER ApplicationName
        A service fabric application name that exists on the provided ring, such as fabric:/NetworkController.
    .PARAMETER ServiceName
        A service fabric service name that is under the provided ApplicationName on the provided ring, such as fabric:/NetworkController/ApiService.
    .PARAMETER ServiceTypeName
        A service fabric service TypeName, such as VSwitchService
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnServiceFabricService -NetworkController 'Prefix-NC01' -Credential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnServiceFabricService -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -ServiceTypeName 'ApiService'
    #>

    [CmdletBinding(DefaultParameterSetName = 'NamedService')]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String]$ApplicationName = 'fabric:/NetworkController',

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [System.String]$ServiceName,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String]$ServiceTypeName,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String[]]$NetworkController = $global:SdnDiagnostics.InfrastructureInfo.NetworkController,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        switch ($PSCmdlet.ParameterSetName) {
            'NamedService' {
                if ($ServiceName) {
                    $sb = {
                        Get-ServiceFabricApplication -ApplicationName $using:ApplicationName | Get-ServiceFabricService -ServiceName $using:ServiceName
                    }
                }
                else {
                    $sb = {
                        Get-ServiceFabricApplication -ApplicationName $using:ApplicationName | Get-ServiceFabricService
                    }
                }
            }

            'NamedServiceTypeName' {
                if ($ServiceTypeName) {
                    $sb = {
                        Get-ServiceFabricApplication -ApplicationName $using:ApplicationName | Get-ServiceFabricService -ServiceTypeName $using:ServiceTypeName
                    }
                }
                else {
                    $sb = {
                        Get-ServiceFabricApplication -ApplicationName $using:ApplicationName | Get-ServiceFabricService
                    }
                }
            }

            default {
                $sb = {
                    Get-ServiceFabricApplication | Get-ServiceFabricService
                }
            }
        }

        if ($NetworkController) {
            Invoke-SdnServiceFabricCommand -NetworkController $NetworkController -ScriptBlock $sb -Credential $Credential
        }
        else {
            Invoke-SdnServiceFabricCommand -ScriptBlock $sb -Credential $Credential
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Set-SdnServiceFabricClusterConfig {
    <#
    .SYNOPSIS
        Gets Service Fabric Cluster Config Properties.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates. Default to local machine.
    .PARAMETER Uri
        The Uri to read properties from ClusterConfiguration, GlobalConfiguration
    .PARAMETER Name
        Property Name to filter the result. If not specified, it will return all properties.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Set-SdnServiceFabricClusterConfig -NetworkController 'NC01' -Uri "ClusterConfiguration" -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]$NetworkController = $(HostName),

        [Parameter(Mandatory = $true)]
        [ValidateSet('GlobalConfiguration', 'ClusterConfiguration')]
        [String]$Uri,

        [Parameter(Mandatory = $true)]
        [String]$Name,

        [Parameter(Mandatory = $true)]
        [System.Object]$Value,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        Connect-ServiceFabricCluster | Out-Null
        $client = [System.Fabric.FabricClient]::new()
        $absoluteUri = "fabric:/NetworkController/$Uri"
        $task = $client.PropertyManager.PutPropertyAsync($absoluteUri, $Name, $Value)
        $task.Wait()
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnNetworkControllerClusterInfo {
    <#
    .SYNOPSIS
        Gather the Network Controller cluster wide info from one of the Network Controller
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER OutputDirectory
        Directory location to save results. It will create a new sub-folder called NetworkControllerClusterInfo that the files will be saved to
    .EXAMPLE
        PS> Get-SdnNetworkControllerClusterInfo
    .EXAMPLE
        PS> Get-SdnNetworkControllerClusterInfo -NetworkController 'NC01' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$NetworkController,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    try {
        [System.IO.FileInfo]$outputDir = Join-Path -Path $OutputDirectory.FullName -ChildPath 'NetworkControllerClusterInfo'

        if (!(Test-Path -Path $outputDir.FullName -PathType Container)) {
            $null = New-Item -Path $outputDir.FullName -ItemType Directory -Force
        }

        Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock { Get-NetworkController } -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-NetworkController" -FileType txt

        Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock { Get-NetworkControllerNode } -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-NetworkControllerNode" -FileType txt

        Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock { Get-NetworkControllerReplica } -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-NetworkControllerReplica" -FileType txt

        Get-SdnServiceFabricClusterHealth -NetworkController $NetworkController -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-SdnServiceFabricClusterHealth" -FileType txt

        Get-SdnServiceFabricApplicationHealth -NetworkController $NetworkController -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-SdnServiceFabricApplicationHealth" -FileType txt

        Get-SdnServiceFabricClusterManifest -NetworkController $NetworkController -Credential $Credential `
        | Out-File -FilePath "$($outputDir.FullName)\Get-SdnServiceFabricClusterManifest.xml"

        $ncServices = Get-SdnServiceFabricService -NetworkController $NetworkController -Credential $Credential
        $ncServices | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-SdnServiceFabricService" -FileType txt
        foreach ($service in $ncServices) {
            Get-SdnServiceFabricReplica -NetworkController $NetworkController -Credential $Credential -ServiceName $service.ServiceName `
            | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-SdnServiceFabricReplica_$($service.ServiceTypeName)" -FileType txt
        }

        Invoke-SdnServiceFabricCommand -NetworkController $NetworkController -Credential $Credential -ScriptBlock { Get-ServiceFabricApplication } `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-ServiceFabricApplication" -FileType json

        Get-SdnServiceFabricNode -NetworkController $NetworkController -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-SdnServiceFabricNode" -FileType txt

    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Wait-NetworkControllerAppHealthy {
    <#
    .SYNOPSIS
        Query the Network Controller App Health Status. Wait for the Network Controller App become healthy when $Interval specified.
    .PARAMETER NetworkController
        Specifies one of the Network Controller VM name.
    .PARAMETER Interval
        App healh status query interval until the App become healthy, default to 0 means no retry of the health status query.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $NetworkController,
        [Parameter(Mandatory = $false)]
        [Int32]
        $Interval = 0,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $scriptBlock = {
            param (
                [Int32]
                $Interval = 0
            )
            $isApplicationHealth = $false;
            Write-Host "[$(HostName)] Query Network Controller App Health"
            while ($isApplicationHealth -ne $true) {
                #Connect-ServiceFabricCluster -X509Credential -FindType FindByThumbprint -FindValue $certThumb  -ConnectionEndpoint "$($NodeFQDN):49006" | Out-Null
                #Cluster should have been back to normal when reach here use default parameters to connect
                Connect-ServiceFabricCluster | Out-Null
                $clusterHealth = Get-ServiceFabricClusterHealth
                if ($clusterHealth.AggregatedHealthState -ne "Ok") {
                    if ($clusterHealth.NodeHealthStates -ne "Ok") {
                        Get-ServiceFabricNode -StatusFilter All | Format-Table Nodename, Nodestatus, HealthState, IpAddressOrFQDN, NodeUptime -autosize
                    }
                    $applicationStatus = Get-ServiceFabricApplication -ApplicationName fabric:/NetworkController
                    if ($applicationStatus.HealthState -ne "Ok") {
                        $applicationStatus | Format-Table ApplicationName, ApplicationStatus, HealthState -AutoSize
                        $services = Get-ServiceFabricService -ApplicationName fabric:/NetworkController
                        $allServiceHealth = $true;
                        foreach ($service in $services) {
                            if ($service.HealthState -notlike "Ok") {
                                $allServiceHealth = $false;
                            }
                        }
                        if ($allServiceHealth -and $services.Count -gt 0) {
                            $isApplicationHealth = $true
                            break
                        }

                        $services | Format-Table ServiceName, ServiceStatus, HealthState -AutoSize
                    }
                    else {
                        $isApplicationHealth = $true
                    }

                    $systemStatus = Get-ServiceFabricService -ApplicationName fabric:/System
                    if ($systemStatus.HealthState -ne "Ok") {
                        $systemStatus | Format-Table ServiceName, ServiceStatus, HealthState -AutoSize
                    }
                }
                else {
                    $isApplicationHealth = $true;
                }

                Write-Host "[$(HostName)] Current Network Controller Health Status: $isApplicationHealth"
                if ($Interval -gt 0) {
                    Start-Sleep -Seconds $Interval
                }
                else {
                    break
                }
            }
        }

        if (-NOT ($PSBoundParameters.ContainsKey('NetworkController'))) {
            Invoke-Command -ScriptBlock $scriptBlock -ArgumentList $Interval
        }
        else {
            Invoke-Command -ComputerName $NetworkController -ScriptBlock $scriptBlock -ArgumentList $Interval -Credential $Credential
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Wait-ServiceFabricClusterHealthy {
    <#
    .SYNOPSIS
        Start the FabricHostSvc on each of the Network Controller VM and wait for the service fabric service to become healthy.
    .PARAMETER NcVMs
        The list of Network Controller VMs.
    .PARAMETER ClusterCredentialType
        X509, Windows or None.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $NcNodeList,

        [Parameter(Mandatory = $true)]
        [hashtable]
        $CertRotateConfig,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [switch]
        $Restart
    )

    try {
        $currentNcNode = $null

        # Start Service Fabric Service for each NC
        foreach ($ncNode in $NcNodeList) {
            if (Test-ComputerNameIsLocal -ComputerName $ncNode.IpAddressOrFQDN) {
                $currentNcNode = $ncNode
            }

            Invoke-PSRemoteCommand -ComputerName $ncNode.IpAddressOrFQDN -ScriptBlock {
                if ($using:Restart) {
                    Stop-Service -Name 'FabricHostSvc' -Force
                    Start-Sleep -Seconds 5
                }

                Start-Service -Name 'FabricHostSvc'
            } -Credential $Credential
        }

        Trace-Output "Sleeping 60s to wait for Serice Fabric Service to be ready"
        Start-Sleep -Seconds 60
        "Waiting for service fabric service healthy" | Trace-Output
        $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName + "." + (get-ciminstance win32_computersystem).Domain
        $certThumb = $CertRotateConfig[$currentNcNode.NodeName.ToLower()]

        $maxRetry = 10
        $clusterConnected = $false
        while ($maxRetry -gt 0) {
            if (!$clusterConnected) {
                try {
                    "Service fabric cluster connect attempt $(11 - $maxRetry)/10" | Trace-Output
                    if ($CertRotateConfig["ClusterCredentialType"] -ieq "X509") {
                        "Connecting to Service Fabric Cluster using cert with thumbprint: {0}" -f $certThumb | Trace-Output
                        Connect-ServiceFabricCluster -X509Credential -FindType FindByThumbprint -FindValue $certThumb  -ConnectionEndpoint "$($NodeFQDN):49006" | Out-Null
                    }
                    else {
                        Connect-ServiceFabricCluster | Out-Null
                    }
                    $clusterConnected = $true
                }
                catch {
                    $maxRetry --
                    continue
                }
            }

            if ($clusterConnected) {
                $services = @()
                $services = Get-ServiceFabricService -ApplicationName fabric:/System
                $allServiceHealth = $true
                if ($services.Count -eq 0) {
                    "No service fabric services retrieved yet" | Trace-Output -Level:Warning
                }

                foreach ($service in $services) {
                    if ($service.ServiceStatus -ne "Active" -or $service.HealthState -ne "Ok" ) {
                        "$($service.ServiceName) ServiceStatus: $($service.ServiceStatus) HealthState: $($service.HealthState)" | Trace-Output -Level:Warning
                        $allServiceHealth = $false
                    }
                }
                if ($allServiceHealth -and $services.Count -gt 0) {
                    "All service fabric service has been healthy" | Trace-Output -Level:Warning
                    return $allServiceHealth
                }

                Start-Sleep -Seconds 10
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Invoke-SdnServiceFabricCommand {
    <#
    .SYNOPSIS
        Connects to the service fabric ring that is used by Network Controller.
    .PARAMETER ScriptBlock
        A script block containing the service fabric commands to invoke.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Invoke-SdnServiceFabricCommand -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -ScriptBlock { Get-ServiceFabricClusterHealth }
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [System.String[]]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true)]
        [ScriptBlock]$ScriptBlock
    )

    if (-NOT ($PSBoundParameters.ContainsKey('NetworkController'))) {
        $config = Get-SdnRoleConfiguration -Role 'NetworkController'
        $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
        if (-NOT ($confirmFeatures)) {
            "The current machine is not a NetworkController, run this on NetworkController or use -NetworkController parameter to specify one" | Trace-Output -Level:Warning
            return # don't throw exception, since this is a controlled scenario and we do not need stack exception tracing
        }
    }

    foreach ($controller in $NetworkController) {

        $i = 0
        $maxRetry = 3

        # due to scenario as described in https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-troubleshoot-local-cluster-setup#cluster-connection-fails-with-object-is-closed
        # we want to catch any exception when connecting to service fabric cluster, and if necassary destroy and create a new remote pssession
        "Invoke Service Fabric cmdlets against {0}" -f $controller | Trace-Output -Level Verbose
        while ($i -lt $maxRetry) {
            $i++

            $session = New-PSRemotingSession -ComputerName $controller -Credential $Credential
            if (!$session) {
                "No session could be established to {0}" -f $controller | Trace-Output -Level:Exception
                break
            }

            try {
                $connection = Invoke-Command -Session $session -ScriptBlock {
                    # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
                    Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null
                } -ErrorAction Stop
            }
            catch {
                "Unable to connect to Service Fabric Cluster. Attempt {0}/{1}`n`t{2}" -f $i, $maxRetry, $_ | Trace-Output -Level:Exception
                "Terminating remote session {0} to {1}" -f $session.Name, $session.ComputerName | Trace-Output -Level:Warning
                Get-PSSession -Id $session.Id | Remove-PSSession
            }
        }

        if (!$connection) {
            "Unable to connect to Service Fabric Cluster" | Trace-Output -Level:Exception
            continue
        }

        "NetworkController: {0}, ScriptBlock: {1}" -f $controller, $ScriptBlock.ToString() | Trace-Output -Level:Verbose
        $sfResults = Invoke-Command -Session $session -ScriptBlock $ScriptBlock

        # if we get results from service fabric, then we want to break out of the loop
        if ($sfResults) {
            break
        }
    }

    if (!$sfResults) {
        throw New-Object System.NullReferenceException("Unable to return results from service fabric")
    }

    if ($sfResults.GetType().IsPrimitive -or ($sfResults -is [String])) {
        return $sfResults
    }
    else {
        return ($sfResults | Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId)
    }
}

function Get-NetworkControllerNodeInfoFromClusterManifest {
    <#
    .SYNOPSIS
        This function is used as fallback method in the event that normal Get-NetworkControllerNode cmdlet fails in scenarios where certs may be expired
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]$NetworkController = $(HostName),

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    "Attempting to retrieve NetworkControllerNode information via ClusterManifest and other methods" | Trace-Output
    $array = @()

    $clusterManifest = [xml](Get-SdnServiceFabricClusterManifest -NetworkController $NetworkController -Credential $Credential)
    $clusterManifest.ClusterManifest.Infrastructure.WindowsServer.NodeList.Node | ForEach-Object {
        $object = [PSCustomObject]@{
            Name            = $_.NodeName
            Server          = $_.IPAddressOrFQDN
            FaultDomain     = $_.FaultDomain
            RestInterface   = $null
            Status          = $null
            NodeCertificate = $null
        }

        $certificate = ($clusterManifest.ClusterManifest.NodeTypes.NodeType | Where-Object Name -ieq $_.NodeName).Certificates.ServerCertificate.X509FindValue.ToString()
        $object | Add-Member -MemberType NoteProperty -Name NodeCertificateThumbprint -Value $certificate

        $array += $object
    }

    return $array
}

function New-NetworkControllerClusterSecret {
    <#
    .SYNOPSIS
        Decrypt the current secret in ClusterManifest and Generate new one if decrypt success.
    .PARAMETER NcVMs
        The list of Network Controller VMs.
    .PARAMETER NcRestName
        The Network Controller REST Name in FQDN format.
    .PARAMETER ManifestFolder
        The Manifest Folder contains the orginal Manifest Files.
    .PARAMETER ManifestFolderNew
        The New Manifest Folder contains the new Manifest Files. Updated manifest file save here.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $OldEncryptedSecret,
        [Parameter(Mandatory = $true)]
        [String]
        $NcRestCertThumbprint,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $decryptedText = Invoke-ServiceFabricDecryptText -CipherText $OldEncryptedSecret

    if ($null -eq $decryptedText) {
        throw New-Object System.NotSupportedException("Failed to decrypt the secret.")
    }

    $newEncryptedSecret = Invoke-ServiceFabricEncryptText -CertThumbPrint $NcRestCertThumbprint -Text $decryptedText -StoreName MY -StoreLocation LocalMachine -CertStore

    $newDecryptedText = Invoke-ServiceFabricDecryptText -CipherText $newEncryptedSecret

    if ($newDecryptedText -eq $decryptedText) {
        "GOOD, new key and old key are same. Ready for use" | Trace-Output
    }
    else {
        throw New-Object System.NotSupportedException("Decrypted text by new certificate is not matching the old one. We cannot continue.")
    }
    if ($null -eq $newEncryptedSecret) {
        throw New-Object System.NotSupportedException("Failed to encrypt the secret with new certificate")
    }

    return $newEncryptedSecret
}

function Update-NetworkControllerCertificateInManifest {
    <#
    .SYNOPSIS
        Update Network Controller Manifest File with new Network Controller Certificate.
    .PARAMETER NcVMs
        The list of Network Controller VMs.
    .PARAMETER ManifestFolder
        The Manifest Folder contains the orginal Manifest Files.
    .PARAMETER ManifestFolderNew
        The New Manifest Folder contains the new Manifest Files. Updated manifest file save here.
    .PARAMETER CertRotateConfig
        The Config generated by New-SdnCertificateRotationConfig to include NC REST certificate thumbprint and node certificate thumbprint.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $NcNodeList,
        [Parameter(Mandatory = $true)]
        [String]
        $ManifestFolder,
        [Parameter(Mandatory = $true)]
        [String]
        $ManifestFolderNew,
        [Parameter(Mandatory = $true)]
        [hashtable]
        $CertRotateConfig,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    if ($NcNodeList.Count -eq 0) {
        throw New-Object System.NotSupportedException("NcNodeList is empty")
    }

    # Prepare the cert thumbprint to be used
    # Update certificates ClusterManifest.current.xml

    $clusterManifestXml = [xml](Get-Content "$ManifestFolder\ClusterManifest.current.xml")

    if ($null -eq $clusterManifestXml) {
        Trace-Output "ClusterManifest not found at $ManifestFolder\ClusterManifest.current.xml" -Level:Error
        throw
    }

    $NcRestCertThumbprint = $CertRotateConfig["NcRestCert"]

    # Update encrypted secret
    # Get encrypted secret from Cluster Manifest
    $fileStoreServiceSection = ($clusterManifestXml.ClusterManifest.FabricSettings.Section | Where-Object name -eq FileStoreService)
    $OldEncryptedSecret = ($fileStoreServiceSection.Parameter | Where-Object Name -eq "PrimaryAccountNTLMPasswordSecret").Value
    $newEncryptedSecret = New-NetworkControllerClusterSecret -OldEncryptedSecret $OldEncryptedSecret -NcRestCertThumbprint $NcRestCertThumbprint -Credential $Credential

    # Update new encrypted secret in Cluster Manifest
    ($fileStoreServiceSection.Parameter | Where-Object Name -eq "PrimaryAccountNTLMPasswordSecret").Value = "$newEncryptedSecret"
    ($fileStoreServiceSection.Parameter | Where-Object Name -eq "SecondaryAccountNTLMPasswordSecret").Value = "$newEncryptedSecret"

    # Update SecretsCertificate to new REST Cert

    Trace-Output "Updating SecretsCertificate with new rest cert thumbprint $NcRestCertThumbprint"
    $clusterManifestXml.ClusterManifest.Certificates.SecretsCertificate.X509FindValue = "$NcRestCertThumbprint"

    $securitySection = $clusterManifestXml.ClusterManifest.FabricSettings.Section | Where-Object Name -eq "Security"
    $ClusterCredentialType = $securitySection.Parameter | Where-Object Name -eq "ClusterCredentialType"

    $infrastructureManifestXml = [xml](Get-Content "$ManifestFolder\InfrastructureManifest.xml")

    # Update Node Certificate to new Node Cert if the ClusterCredentialType is X509 certificate
    if ($ClusterCredentialType.Value -eq "X509") {
        foreach ($node in $clusterManifestXml.ClusterManifest.NodeTypes.NodeType) {
            $ncNode = $node.Name
            $ncNodeCertThumbprint = $CertRotateConfig[$ncNode.ToLower()]
            Write-Verbose "Updating node $ncNode with new thumbprint $ncNodeCertThumbprint"
            $node.Certificates.ClusterCertificate.X509FindValue = "$ncNodeCertThumbprint"
            $node.Certificates.ServerCertificate.X509FindValue = "$ncNodeCertThumbprint"
            $node.Certificates.ClientCertificate.X509FindValue = "$ncNodeCertThumbprint"
        }

        # Update certificates InfrastructureManifest.xml

        foreach ($node in $infrastructureManifestXml.InfrastructureInformation.NodeList.Node) {
            $ncNodeCertThumbprint = $CertRotateConfig[$node.NodeName.ToLower()]
            $node.Certificates.ClusterCertificate.X509FindValue = "$ncNodeCertThumbprint"
            $node.Certificates.ServerCertificate.X509FindValue = "$ncNodeCertThumbprint"
            $node.Certificates.ClientCertificate.X509FindValue = "$ncNodeCertThumbprint"
        }
    }

    # Update certificates for settings.xml
    foreach ($ncNode in $NcNodeList) {
        $ncVm = $ncNode.IpAddressOrFQDN
        $settingXml = [xml](Get-Content "$ManifestFolder\$ncVm\Settings.xml")
        if ($ClusterCredentialType.Value -eq "X509") {
            $ncNodeCertThumbprint = $CertRotateConfig[$ncNode.NodeName.ToLower()]
            $fabricNodeSection = $settingXml.Settings.Section | Where-Object Name -eq "FabricNode"
            $parameterToUpdate = $fabricNodeSection.Parameter | Where-Object Name -eq "ClientAuthX509FindValue"
            $parameterToUpdate.Value = "$ncNodeCertThumbprint"
            $parameterToUpdate = $fabricNodeSection.Parameter | Where-Object Name -eq "ServerAuthX509FindValue"
            $parameterToUpdate.Value = "$ncNodeCertThumbprint"
            $parameterToUpdate = $fabricNodeSection.Parameter | Where-Object Name -eq "ClusterX509FindValue"
            $parameterToUpdate.Value = "$ncNodeCertThumbprint"
        }

        # Update encrypted secret in settings.xml
        $fileStoreServiceSection = $settingXml.Settings.Section | Where-Object Name -eq "FileStoreService"
        ($fileStoreServiceSection.Parameter | Where-Object Name -eq "PrimaryAccountNTLMPasswordSecret").Value = "$newEncryptedSecret"
        ($fileStoreServiceSection.Parameter | Where-Object Name -eq "SecondaryAccountNTLMPasswordSecret").Value = "$newEncryptedSecret"

        $settingXml.Save("$ManifestFolderNew\$ncVm\Settings.xml")
    }

    $infrastructureManifestXml.Save("$ManifestFolderNew\InfrastructureManifest.xml")
    $clusterManifestXml.Save("$ManifestFolderNew\ClusterManifest.current.xml")
}

function Update-ServiceFabricCluster {
    <#
    .SYNOPSIS
        Upgrade the Service Fabric Cluster via Start-ServiceFabricClusterUpgrade and wait for the cluster to become healthy.
    .PARAMETER NcNodeList
        The list of Network Controller Nodes.
    .PARAMETER ClusterCredentialType
        X509, Windows or None.
    .PARAMETER ManifestFolderNew
        The New Manifest Folder contains the new Manifest Files.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $NcNodeList,
        [Parameter(Mandatory = $true)]
        [String]
        $ManifestFolderNew,
        [Parameter(Mandatory = $true)]
        [hashtable]
        $CertRotateConfig,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    if ($NcNodeList.Count -eq 0) {
        throw New-Object System.NotSupportedException("NcNodeList is empty")
    }

    # Update the cluster manifest version to 1
    $clusterManifestXml = [xml](Get-Content "$ManifestFolderNew\ClusterManifest.current.xml")
    $currentVersionArray = $clusterManifestXml.ClusterManifest.Version.Split('.')
    $minorVersionIncrease = [int]$currentVersionArray[$currentVersionArray.Length - 1] + 1
    $currentVersionArray[$currentVersionArray.Length - 1] = $minorVersionIncrease
    $newVersionString = $currentVersionArray -Join '.'
    "Upgrade Service Fabric from $($clusterManifestXml.ClusterManifest.Version) to $newVersionString" | Trace-Output
    $clusterManifestXml.ClusterManifest.Version = $newVersionString
    $clusterManifestXml.Save("$ManifestFolderNew\ClusterManifest_new.xml")

    $currentNcNode = $null
    # Start Service Fabric Service for each NC
    foreach ($ncNode in $NcNodeList) {
        if (Test-ComputerNameIsLocal -ComputerName $ncNode.IpAddressOrFQDN) {
            $currentNcNode = $ncNode
        }
    }
    $certThumb = $CertRotateConfig[$currentNcNode.NodeName.ToLower()]

    $clusterManifestPath = "$ManifestFolderNew\ClusterManifest_new.xml"

    if (!(Test-Path $clusterManifestPath)) {
        Throw "Path $clusterManifestPath not found"
    }

    "Upgrading Service Fabric Cluster with ClusterManifest at $clusterManifestPath" | Trace-Output

    # Sometimes access denied returned for the copy call, retry here to workaround this.
    $maxRetry = 3
    while ($maxRetry -gt 0) {
        try {
            if ($CertRotateConfig["ClusterCredentialType"] -ieq "X509") {
                "Connecting to Service Fabric Cluster using cert with thumbprint: {0}" -f $certThumb | Trace-Output
                Connect-ServiceFabricCluster -X509Credential -FindType FindByThumbprint -FindValue $certThumb -ConnectionEndpoint "$($currentNcNode.IpAddressOrFQDN):49006" | Out-Null
            }
            else {
                Connect-ServiceFabricCluster | Out-Null
            }
            Copy-ServiceFabricClusterPackage -Config -ImageStoreConnectionString "fabric:ImageStore" -ClusterManifestPath  $clusterManifestPath -ClusterManifestPathInImageStore "ClusterManifest.xml"
            break
        }
        catch {
            "Copy-ServiceFabricClusterPackage failed with exception $_.Exception. Retry $(4 - $maxRetry)/3 after 60 seconds" | Trace-Output -Level:Warning
            Start-Sleep -Seconds 60
            $maxRetry --
        }
    }

    Register-ServiceFabricClusterPackage -Config -ClusterManifestPath "ClusterManifest.xml"
    Start-ServiceFabricClusterUpgrade -ClusterManifestVersion $NewVersionString -Config -UnmonitoredManual -UpgradeReplicaSetCheckTimeoutSec 30

    while ($true) {
        $upgradeStatus = Get-ServiceFabricClusterUpgrade
        "Current upgrade state: $($upgradeStatus.UpgradeState) UpgradeDomains: $($upgradeStatus.UpgradeDomains)" | Trace-Output
        if ($upgradeStatus.UpgradeState -eq "RollingForwardPending") {
            $nextNode = $upgradeStatus.NextUpgradeDomain
            "Next node to upgrade $nextNode" | Trace-Output
            try {
                Resume-ServiceFabricClusterUpgrade -UpgradeDomainName $nextNode
                # Catch exception for resume call, as sometimes, the upgrade status not updated intime caused duplicate resume call.
            }
            catch {
                "Exception in Resume-ServiceFabricClusterUpgrade $_.Exception" | Trace-Output -Level:Warning
            }
        }
        elseif ($upgradeStatus.UpgradeState -eq "Invalid" `
                -or $upgradeStatus.UpgradeState -eq "Failed") {
            Throw "Something wrong with the upgrade"
        }
        elseif ($upgradeStatus.UpgradeState -eq "RollingBackCompleted" `
                -or $upgradeStatus.UpgradeState -eq "RollingForwardCompleted") {
            "Upgrade has been completed" | Trace-Output
            break
        }
        else {
            "Waiting for current node upgrade to complete" | Trace-Output
        }

        Start-Sleep -Seconds 60
    }
}
