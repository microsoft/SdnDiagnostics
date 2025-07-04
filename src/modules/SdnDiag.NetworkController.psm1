# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Import-Module $PSScriptRoot\SdnDiag.Common.psm1
Import-Module $PSScriptRoot\SdnDiag.Utilities.psm1
Import-Module $PSScriptRoot\SdnDiag.NetworkController.FC.psm1
Import-Module $PSScriptRoot\SdnDiag.NetworkController.SF.psm1

$configurationData = Import-PowerShellDataFile -Path $PSScriptRoot\SdnDiag.NetworkController.Config.psd1
New-Variable -Name 'SdnDiagnostics_NC' -Scope 'Script' -Force -Value @{
    Config = $configurationData
}

##########################
#### CLASSES & ENUMS #####
##########################

class SdnFabricInfrastructure {
    [System.String[]]$NetworkController
    [System.String[]]$LoadBalancerMux
    [System.String[]]$Gateway
    [System.String]$NcUrl
    [System.String]$RestApiVersion
    [System.String[]]$FabricNodes
}

enum SdnApiResource {
    AccessControlLists
    AuditingSettingsConfig
    Credentials
    Discovery
    GatewayPools
    Gateways
    IDNSServerConfig
    LearnedIPAddresses
    LoadBalancerManagerConfig
    LoadBalancerMuxes
    LoadBalancers
    LogicalNetworks
    MacPools
    NetworkControllerBackup
    NetworkControllerRestore
    NetworkControllerStatistics
    NetworkInterfaces
    Operations
    OperationResults
    PublicIPAddresses
    SecurityTags
    Servers
    ServiceInsertions
    RouteTables
    VirtualGateways
    VirtualNetworkManagerConfig
    VirtualNetworks
    VirtualServers
    VirtualSwitchManagerConfig
}

##########################
#### ARG COMPLETERS ######
##########################

##########################
####### FUNCTIONS ########
##########################

function Connect-SlbManager {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $slbClient = Get-SlbClient -ErrorAction Stop

    # we need identify the current primary replica for the slbmanager service
    # if the primary replica is on the local node, then we will use the loopback address
    $slbManagerPrimary = Get-SdnServiceFabricReplica -ServiceTypeName 'SlbManagerService' -Primary -Credential $Credential -ErrorAction Stop
    if ($null -ieq $slbManagerPrimary) {
        throw "Unable to return primary replica of SlbManagerService"
    }

    $slbManagerPrimaryNodeName = $slbManagerPrimary.ReplicaAddress.Split(':')[0]
    if (Test-ComputerNameIsLocal -ComputerName $slbManagerPrimaryNodeName) {
        $useLoopback = $true
    }

    # if we have already detected that we are using the loopback address, then we can just use that
    # otherwise we will test to check if the SlbManagerPrimary is an IP address or a hostname
    # if it is a hostname, then we will resolve it to an IP address
    if ($useLoopback) {
        $ipAddress = [System.Net.IPAddress]::Loopback
    }
    else {
        $isIpAddress = ($slbManagerPrimaryNodeName -as [IPAddress]) -as [Bool]
        if (!$isIpAddress) {
            [IPAddress]$ipAddress = [System.Net.Dns]::GetHostAddresses($slbManagerPrimaryNodeName)[0].IPAddressToString
            "Resolved {0} to {1}" -f $slbManagerPrimaryNodeName, $ipAddress.IPAddressToString | Trace-Output -Level:Verbose
        }
        else {
            [IPAddress]$ipAddress = $slbManagerPrimaryNodeName
        }
    }

    # create IPEndPoint object for the SlbManagerPrimary address and port 49001
    $endpoint = New-Object System.Net.IPEndPoint($ipAddress, 49001)
    $networkControllerNode = Get-SdnNetworkControllerSFNode -Name $env:COMPUTERNAME

    # check to see if we have a node certificate that will be used for establishing connectivity
    # otherwise if not using x509 between the NC nodes we can just use $null
    if ($networkControllerNode.NodeCertificate.Thumbprint) {
        $slbmConnection = $slbClient.ConnectToSlbManager($endpoint, $networkControllerNode.NodeCertificate.Thumbprint, $null)
    }
    else {
        $slbmConnection = $slbClient.ConnectToSlbManager($endpoint, $null, $null)
    }

    return $slbmConnection
}

function Get-ManagementAddress {
    param (
        $ManagementAddress
    )

    $uniqueFQDN = @()
    $uniqueIPAddress = @()

    foreach ($ma in $ManagementAddress) {
        $isIpAddress = ($ma -as [IPAddress]) -as [Bool]
        if ($isIpAddress) {
            $uniqueIPAddress += $ma
        }
        else {
            $uniqueFQDN += $ma.ToLower()
        }
    }

    # if we have a mix of FQDN and IPAddress, defer to FQDN
    # use Sort-Object -Unique to remove duplicates from the list (case insensitive)
    if ($uniqueFQDN) {
        return ($uniqueFQDN | Sort-Object -Unique)
    }
    else {
        return ($uniqueIPAddress | Sort-Object -Unique)
    }
}

function Get-NetworkControllerConfigState {
    <#
    .SYNOPSIS
        Outputs a set of configuration state files for the network controller role.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .EXAMPLE
        PS> Get-NetworkControllerConfigState -OutputDirectory "C:\Temp\CSS_SDN"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    $currentErrorActionPreference = $ErrorActionPreference
    $ProgressPreference = 'SilentlyContinue'
    $ErrorActionPreference = 'SilentlyContinue'
    [string]$outDir = Join-Path -Path $OutputDirectory.FullName -ChildPath "ConfigState\NetworkController"

    try {
        $config = Get-SdnModuleConfiguration -Role 'NetworkController'
        "Collect configuration state details for role {0}" -f $config.Name | Trace-Output
        [string]$ncAppDir = Join-Path $outDir -ChildPath "Application"
        if (-NOT (Initialize-DataCollection -Role $config.Name -FilePath $ncAppDir -MinimumMB 20)) {
            "Unable to initialize environment for data collection" | Trace-Output -Level:Error
            return
        }

        [string]$regDir = Join-Path -Path $outDir -ChildPath "Registry"
        Export-RegistryKeyConfigDetails -Path $config.properties.regKeyPaths -OutputDirectory $regDir

        # enumerate dll binary version for NC application
        $ncAppDirectories = Get-ChildItem -Path "$env:SystemRoot\NetworkController" -Directory
        foreach($directory in $ncAppDirectories){
            [string]$fileName = "FileInfo_{0}" -f $directory.BaseName
            Get-Item -Path "$($directory.FullName)\*" -Include *.dll,*.exe | Export-ObjectToFile -FilePath $ncAppDir -Name $fileName -FileType txt -Format List
        }

        switch ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType) {
            'ServiceFabric' {
                Get-NetworkControllerSFConfigState @PSBoundParameters
            }
            'FailoverCluster' {
                Get-NetworkControllerFCConfigState @PSBoundParameters
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }

    $ProgressPreference = 'Continue'
    $ErrorActionPreference = $currentErrorActionPreference
}

function Get-PublicIpReference {
    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [uri]$NcUri,

        [Parameter(Mandatory = $true)]
        [System.Object]$IpConfiguration,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    $restParams = @{
        NcUri = $NcUri
    }
    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $restParams.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $restParams.Add('NcRestCredential', $NcRestCredential)
        }
    }

    try {
        # check for an instance-level public IP address that is directly associated
        # with the ipconfiguration and return back to calling function
        if ($IpConfiguration.properties.publicIPAddress) {
            "Located {0} associated with {1}" -f $IpConfiguration.properties.publicIPAddress.resourceRef, $IpConfiguration.resourceRef | Trace-Output -Level:Verbose
            return ($IpConfiguration.properties.publicIPAddress.resourceRef)
        }
        else {
            "Unable to locate an instance-level public IP address associated with {0}" -f $IpConfiguration.resourceRef | Trace-Output -Level:Verbose
        }

        # NIC is connected to a load balancer with public IP association
        # or NIC is not associated to a public IP by any means and instead is connected via implicit load balancer attached to a virtual network
        "Checking for any backend address pool associated with {0}" -f $IpConfiguration.resourceRef | Trace-Output -Level:Verbose
        if ($IpConfiguration.properties.loadBalancerBackendAddressPools) {
            "Located backend address pool associations for {0}" -f $IpConfiguration.resourceRef | Trace-Output -Level:Verbose
            $allBackendPoolRefs = @($IpConfiguration.properties.loadBalancerBackendAddressPools.resourceRef)

            $loadBalancers = Get-SdnResource -Resource:LoadBalancers @restParams
            $backendHash = [System.Collections.Hashtable]::new()
            foreach ($group in $loadBalancers.properties.backendAddressPools | Group-Object resourceRef) {
                [void]$backendHash.Add($group.Name, $group.Group)
            }

            foreach ($backendPoolRef in $allBackendPoolRefs) {
                "Checking for outboundNatRules for {0}" -f $backendPoolRef | Trace-Output -Level:Verbose
                $bePool = $backendHash[$backendPoolRef]

                if ($bePool.properties.outboundNatRules) {
                    "Located outboundNatRule associated with {0}" -f $bePool.resourceRef | Trace-Output -Level:Verbose

                    $obRuleRef = $bePool.properties.outboundNatRules[0].resourceRef
                    break
                }
            }

            if ($obRuleRef) {
                $natRule = $loadBalancers.properties.outboundNatRules | Where-Object { $_.resourceRef -eq $obRuleRef }
                $frontendConfig = $loadBalancers.properties.frontendIPConfigurations | Where-Object { $_.resourceRef -eq $natRule.properties.frontendIPConfigurations[0].resourceRef }

                "Located {0} associated with {0}" -f $frontendConfig.resourceRef, $natRule.resourceRef | Trace-Output -Level:Verbose
                return ($frontendConfig.properties.publicIPAddress.resourceRef)
            }
            else {
                "Unable to locate outboundNatRules associated with {0}" -f $IpConfiguration.properties.loadBalancerBackendAddressPools.resourceRef | Trace-Output -Level:Verbose
            }
        }
        else {
            "Unable to locate any backend pools associated with {0}" -f $IpConfiguration.resourceRef | Trace-Output -Level:Verbose
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }

    return $null
}

function Get-SdnClusterType {
    <#
    .SYNOPSIS
        Determines the cluster type of the Network Controller
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnClusterType
    .EXAMPLE
        PS> Get-SdnClusterType -NetworkController 'NC01' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$NetworkController,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sb = {
        # with failover cluster, the SDNApiService will run as a service within windows
        # so we can check if the service exists to determine if it is a failover cluster configuration regardless if running
        $service = Get-Service -Name 'SDNApiService' -ErrorAction Ignore
        if ($service) {
            return 'FailoverCluster'
        }

        return 'ServiceFabric'
    }

    if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
        [string]$result = Invoke-Command -ScriptBlock $sb
    }
    else {
        [string]$result = Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock $sb -Credential $Credential
    }

    "Cluster Type: $result" | Trace-Output -Level:Verbose
    return $result
}

function Get-SdnDipProbeInfoFromHost {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [IPAddress[]]$HostIPAddress,

        [Parameter(Mandatory = $false)]
        [System.String]$ProbeID = $null
    )

    $slbManager = Connect-SlbManager -ErrorAction Stop
    if ($slbManager) {
        $dipProbeInfo = $slbManager.GetDipProbeInfoFromHost($HostIPAddress, $ProbeID)
        return $dipProbeInfo
    }
}

function Get-SdnDiscovery {
    <#
    .SYNOPSIS
        Calls to the Discovery API endpoint to determine versioning and feature details
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate
    )

    $ncRestParams = @{
        NcUri = $NcUri
        Resource = 'Discovery'
    }
    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $ncRestParams.Add('NcRestCredential', $NcRestCredential)
        }
    }

    try {
        $result = Get-SdnResource @ncRestParams
        return $result
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnNetworkControllerRestURL {
    <#
        .SYNOPSIS
        Queries Network Controller to identify the Rest URL endpoint that can be used to query the north bound API endpoint.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    # if already populated into the cache, return the value
    if (-NOT ([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.EnvironmentInfo.NcUrl))) {
        return $Global:SdnDiagnostics.EnvironmentInfo.NcUrl
    }

    try {
        switch ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType) {
            'FailoverCluster' {
                $result = Get-SdnNetworkControllerFC @PSBoundParameters -ErrorAction Stop
                if ($result) {
                    $endpoint = $result.RestCertificateSubjectName
                }
            }
            'ServiceFabric' {
                $result = Get-SdnNetworkControllerSF @PSBoundParameters -ErrorAction Stop
                if ($result) {
                    $endpoint = $result.ServerCertificate.Subject.Split('=')[1]
                }
            }
        }
    }
    catch {
        $_ | Trace-Exception
        throw $_
    }

    if (-NOT [string]::IsNullOrEmpty($endpoint)) {
        $ncUrl = 'https://{0}' -f $endpoint
        return $ncUrl
    }
    else {
        throw New-Object System.NullReferenceException("Failed to retrieve Network Controller Rest URL.")
    }
}

function Get-SdnVipState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [IPAddress]$VirtualIPAddress
    )

    $slbManager = Connect-SlbManager -ErrorAction Stop
    if ($slbManager) {
        $vipState = $slbManager.GetVipState($VirtualIPAddress)
        return $vipState
    }
}

function Get-SdnVirtualServer {
    <#
    .SYNOPSIS
        Returns virtual server of a particular resource Id from network controller.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    .PARAMETER ResourceRef
        Specifies Resource Ref of virtual server.
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $true)]
        [String]$ResourceRef,

        [Parameter(Mandatory = $false)]
        [switch]$ManagementAddressOnly,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate
    )

    $restParams = @{
        NcUri = $NcUri
        ResourceRef = $ResourceRef
    }
    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $restParams.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $restParams.Add('NcRestCredential', $NcRestCredential)
        }
    }

    try {
        $result = Get-SdnResource @restParams

        foreach ($obj in $result) {
            if ($obj.properties.provisioningState -ne 'Succeeded') {
                "{0} is reporting provisioningState: {1}" -f $obj.resourceId, $obj.properties.provisioningState | Trace-Output -Level:Warning
            }
        }

        if ($ManagementAddressOnly) {
            $connections = (Get-ManagementAddress -ManagementAddress $result.properties.connections.managementAddresses)
            return $connections
        }
        else {
            return $result
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SlbClient {
    [CmdletBinding()]
    param()

    # as we are dependent on the assemblies contained on Network Controller
    # we need to ensure we are running on Network Controller
    $config = Get-SdnModuleConfiguration -Role 'NetworkController'
    $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
    if (-NOT ($confirmFeatures)) {
        throw New-Object System.NotSupportedException("The current machine is not a NetworkController, run this on NetworkController.")
    }

    $rootDir = "$env:SystemRoot\NetworkController"
    $null = [Reflection.Assembly]::LoadFrom("$rootDir\SharedAssemblies\Microsoft.CloudNet.Slb.Utilities.SlbClient.dll");
    $null = [Reflection.Assembly]::LoadFrom("$rootDir\Framework\Microsoft.NetworkController.Utilities.dll");
    $null = [Reflection.Assembly]::LoadFrom("$rootDir\Framework\Microsoft.NetworkController.ServiceModule.dll");

    [Microsoft.Cloudnet.Slb.Utilities.SlbClient.SlbManagerConnectionFactory]::SlbClientInitializeWithDefaultSettings();
    [Microsoft.Cloudnet.Slb.Utilities.SlbClient.SlbManagerConnectionFactory]::UseInteractiveLogon = $false
    [Microsoft.Cloudnet.Slb.Utilities.SlbClient.SlbManagerConnectionFactory]::EnableBlockingNotifications = $true;

    $slbClient = [Microsoft.Cloudnet.Slb.Utilities.SlbClient.SlbClient]::new()
    return $slbClient
}

function Invoke-SdnNetworkControllerStateDump {
    <#
    .SYNOPSIS
        Executes a PUT operation against REST API endpoint for Network Controller to trigger a IMOS dump of Network Controller services.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    .PARAMETER ExecutionTimeout
        Specify the execution timeout (seconds) on how long you want to wait for operation to complete before cancelling operation. If omitted, defaults to 300 seconds.
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [uri]$NcUri,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate,

        [Parameter(Mandatory = $false)]
        [int]$ExecutionTimeOut = 300,

        [Parameter(Mandatory = $false)]
        [int]$PollingInterval = 1
    )

    $putParams = @{
        Uri             = $null
        Method          = 'Put'
        Headers         = @{"Accept" = "application/json" }
        Content         = "application/json; charset=UTF-8"
        Body            = "{}"
        UseBasicParsing = $true
    }

    $confirmParams = @{
        UseBasicParsing = $true
        TimeoutInSec = $ExecutionTimeOut
    }

    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $confirmParams.Add('NcRestCertificate', $NcRestCertificate)
            $putParams.Add('Certificate', $NcRestCertificate)
        }
        'RestCredential' {
            $confirmParams.Add('NcRestCredential', $NcRestCredential)
            $putParams.Add('Credential', $NcRestCredential)
        }
    }

    [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri -ResourceRef 'diagnostics/networkControllerState'
    $putParams.Uri = $uri

    try {
        # trigger IMOS dump
        "Generate In Memory Object State (IMOS) dump by executing PUT operation against {0}" -f $uri | Trace-Output
        $null = Invoke-WebRequestWithRetry @putParams

        # monitor until the provisionState for the object is not in 'Updating' state
        if (-NOT (Confirm-ProvisioningStateSucceeded -NcUri $putParams.Uri @confirmParams)) {
            throw New-Object System.Exception("Unable to generate IMOS dump")
        }
        else {
            return $true
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }

    return $false
}

function Test-NetworkControllerIsHealthy {
    try {
        $null = Get-NetworkController -ErrorAction 'Stop'
        return $true
    }
    catch {
        "Network Controller is not healthy" | Trace-Output -Level:Error
        return $false
    }
}

function Update-NetworkControllerCredentialResource {
    <#
    .SYNOPSIS
        Update the Credential Resource in Network Controller with new certificate.
    .PARAMETER NcUri
        The Network Controller REST URI.
    .PARAMETER RestCert
        The new Network Controller REST Certificate to be used by credential resource.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $NcUri,

        [Parameter(Mandatory = $true)]
        [X509Certificate]$RestCert,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate
    )
    $putParams = @{
        Uri             = $null
        Method          = 'Put'
        Headers         = @{"Accept" = "application/json" }
        Content         = "application/json; charset=UTF-8"
        Body            = "{}"
        UseBasicParsing = $true
    }
    $confirmStateParams = @{
        TimeoutInSec = 600
        UseBasicParsing = $true
    }
    $ncRestParams = @{
        NcUri = $NcUri
    }

    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $confirmStateParams.Add('NcRestCertificate', $NcRestCertificate)
            $putParams.Add('Certificate', $NcRestCertificate)
            $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $confirmStateParams.Add('NcRestCredential', $NcRestCredential)
            $putParams.Add('Credential', $NcRestCredential)
            $ncRestParams.Add('NcRestCredential', $NcRestCredential)
        }
    }

    $servers = Get-SdnServer @ncRestParams
    foreach ($object in $servers) {
        "Processing X509 connections for {0}" -f $object.resourceRef | Trace-Output
        foreach ($connection in $servers.properties.connections | Where-Object { $_.credentialType -ieq "X509Certificate" -or $_.credentialType -ieq "X509CertificateSubjectName" }) {
            $cred = Get-SdnResource @ncRestParams -ResourceRef $connection.credential.resourceRef

            switch ($cred.properties.type) {
                'X509Certificate' {
                    [string]$newValue = $RestCert.Thumbprint
                }
                'X509CertificateSubjectName' {
                    [string]$newValue = $RestCert.Subject.Split('=')[1].Trim()
                }
            }

            # check if the credential resource already has the new value
            # if it does, then we can skip the update
            if ($cred.properties.value -ieq $newValue) {
                "{0} has already updated to {1}" -f $cred.resourceRef, $newValue | Trace-Output
                continue
            }

            "{0} will be updated from {1} to {2}" -f $cred.resourceRef, $cred.properties.value, $newValue | Trace-Output
            $cred.properties.value = $newValue
            $putParams.Body = $cred | ConvertTo-Json -Depth 100
            $putParams.Uri = Get-SdnApiEndpoint -NcUri $NcUri -ResourceRef $cred.resourceRef

            # update the credential resource with new certificate details
            # and confirm the provisioning state is succeeded
            $null = Invoke-WebRequestWithRetry @putParams
            try {
                Confirm-ProvisioningStateSucceeded -NcUri $putParams.Uri @confirmStateParams
            }
            catch {
                $_ | Trace-Exception
                $_ | Write-Error
            }
        }
    }
}

function Get-SdnApiEndpoint {
    <#
    .SYNOPSIS
        Used to construct the URI endpoint for Network Controller NB API
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER ApiVersion
        The API version to use when invoking against the NC REST API endpoint. By default, reads from $Global:SdnDiagnostics.EnvironmentInfo.RestApiVersion
        which defaults to 'v1' unless explicity overwritten, or 'Get-SdnInfrastructureInfo' is called.
    .PARAMETER ResourceName
        Network Controller resource exposed via NB API interface of Network Controller, as defined under https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ncnbi/6dbabf43-0fcd-439c-81e2-7eb794f7c140.
    .PARAMETER OperationId
        Operation ID for diagnostics operation. This is optional and only used for certain resources.
    .PARAMETER ResourceRef
        The exact resource reference in format of /resourceName/{resourceId}/childObject/{resourceId}
    .EXAMPLE
        PS> Get-SdnApiEndpoint -NcUri $NcUri.AbsoluteUri -ResourceName 'VirtualNetworks'
    .EXAMPLE
        PS> Get-SdnApiEndpoint -NcUri $NcUri.AbsoluteUri -ResourceName '/virtualnetworks/contoso-vnet01'
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceName')]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceName')]
        [System.String]$ApiVersion = $Global:SdnDiagnostics.EnvironmentInfo.RestApiVersion,

        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceName')]
        [System.String]$ResourceName,

        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceName')]
        [System.String]$OperationId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceRef')]
        [System.String]$ResourceRef
    )

    switch ($PSCmdlet.ParameterSetName) {
        'ResourceRef' {
            $ResourceRef = $ResourceRef.TrimStart('/')
            if ($resourceRef -ilike "Discovery*") {
                [System.String]$endpoint = "{0}/networking/{1}" -f $NcUri.AbsoluteUri.TrimEnd('/'), $ResourceRef
            }
            else {
                [System.String]$endpoint = "{0}/networking/{1}/{2}" -f $NcUri.AbsoluteUri.TrimEnd('/'), $ApiVersion, $ResourceRef
            }
        }
        'ResourceName' {
            $apiEndpointProperties = $Script:SdnDiagnostics_NC.Config.Properties.ApiResources[$ResourceName]
            if ([string]::IsNullOrEmpty($apiEndpointProperties.minVersion)) {
                [System.String]$endpoint = "{0}/networking/{1}" -f $NcUri.AbsoluteUri.TrimEnd('/'), $apiEndpointProperties.uri
            }
            else {
                [System.String]$endpoint = "{0}/networking/{1}/{2}" -f $NcUri.AbsoluteUri.TrimEnd('/'), $ApiVersion, $apiEndpointProperties.uri
            }

            if ($apiEndpointProperties.operationId -and (-NOT ([System.String]::IsNullOrEmpty($OperationId)))) {
                $endpoint = "{0}/{1}" -f $endpoint, $OperationId
            }
        }
    }

    $endpoint = $endpoint.TrimEnd('/')
    "Endpoint: {0}" -f $endpoint | Trace-Output -Level:Verbose

    return $endpoint
}

function Get-SdnAuditLog {
    <#
    .SYNOPSIS
        Collects the audit logs for Network Security Groups (NSG) from the hypervisor hosts
    .PARAMETER OutputDirectory
        Directory the results will be saved to. If ommitted, will default to the current working directory.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Credential
        Specifies a user account that has permission to access the Computers. The default is the current user.
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$OutputDirectory = "$(Get-WorkingDirectory)\AuditLogs",

        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate,

        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $ncRestParams = @{
        NcUri = $NcUri
    }
    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $ncRestParams.Add('NcRestCredential', $NcRestCredential)
        }
    }

    $auditSettings = Get-SdnAuditLogSetting @ncRestParams
    if (-NOT $auditSettings.Enabled) {
        "Audit logging is not enabled" | Trace-Output
        return
    }

    # if $ComputerName was not specified, then attempt to locate the servers within the SDN fabric
    # only add the servers where auditingEnabled has been configured as 'Firewall'
    if ($null -eq $ComputerName) {
        $sdnServers = Get-SdnResource @ncRestParams -Resource Servers -ApiVersion $currentRestVersion `
        | Where-Object {$_.properties.auditingEnabled -ieq 'Firewall'}

        $ComputerName = ($sdnServers.properties.connections | Where-Object {$_.credentialType -ieq 'UsernamePassword'}).managementAddresses
    }

    $ComputerName | ForEach-Object {
        "Collecting audit logs from {0}" -f $_ | Trace-Output
        $outputDir = Join-Path -Path $OutputDirectory -ChildPath $_.ToLower()
        Copy-FileFromRemoteComputer -ComputerName $_ -Credential $Credential -Path $auditSettings.Path -Destination $outputDir -Recurse -Force
    }
}

function Get-SdnGateway {
    <#
    .SYNOPSIS
        Returns a list of gateways from network controller.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER ResourceId
        Specifies the unique identifier for the resource.
    .PARAMETER ResourceRef
        Specifies the resource reference for the resource.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    .PARAMETER ManagementAddressOnly
        Optional parameter to only return back the Management Address value.
    .EXAMPLE
        PS> Get-SdnGateway -NcUri 'https://NC.FQDN' -NcRestCredential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnGateway -NcUri 'https://NC.FQDN' -NcRestCredential (Get-Credential) -ManagementAddressOnly
    .EXAMPLE
        PS> Get-SdnGateway -NcUri 'https://NC.FQDN' -NcRestCredential (Get-Credential) -ResourceId 'f5e3b3e0-1b7a-4b9e-8b9e-5b5e3b3e0f5e'
    .EXAMPLE
        PS> Get-SdnGateway -NcUri 'https://NC.FQDN' -NcRestCredential (Get-Credential) -ResourceRef 'gateways/f5e3b3e0-1b7a-4b9e-8b9e-5b5e3b3e0f5e'
    .EXAMPLE
        PS> Get-SdnGateway -NcUri 'https://NC.FQDN' -NcRestCredential (Get-Credential) -ResourceId 'f5e3b3e0-1b7a-4b9e-8b9e-5b5e3b3e0f5e' -ManagementAddressOnly
    .EXAMPLE
        PS> Get-SdnGateway -NcUri 'https://NC.FQDN' -NcRestCredential (Get-Credential) -ResourceRef 'gateways/f5e3b3e0-1b7a-4b9e-8b9e-5b5e3b3e0f5e' -ManagementAddressOnly
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceId')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceRef')]
        [Uri]$NcUri,

        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceId')]
        [String]$ResourceId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceRef')]
        [String]$ResourceRef,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceId')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [X509Certificate]$NcRestCertificate,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceId')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceId')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [switch]$ManagementAddressOnly
    )

    $ncRestParams = @{
        NcUri = $NcUri
    }
    if ($PSBoundParameters.ContainsKey('NcRestCertificate')) {
        $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
    }
    else {
        $ncRestParams.Add('NcRestCredential', $NcRestCredential)
    }

    try {
        switch ($PSCmdlet.ParameterSetName) {
            'ResourceId' {
                $result = Get-SdnResource @ncRestParams -Resource 'Gateways' -ResourceId $ResourceId
            }
            'ResourceRef' {
                $result = Get-SdnResource @ncRestParams -ResourceRef $ResourceRef
            }
            default {
                $result = Get-SdnResource @ncRestParams -Resource 'Gateways'
            }
        }

        if ($result) {
            foreach($obj in $result){
                if($obj.properties.provisioningState -ne 'Succeeded'){
                    "{0} is reporting provisioningState: {1}" -f $obj.resourceId, $obj.properties.provisioningState | Trace-Output -Level:Warning
                }
            }

            if($ManagementAddressOnly){
                $connections = @()
                foreach ($resource in $result) {
                    $virtualServerMgmtAddress = Get-SdnVirtualServer @ncRestParams -ResourceRef $resource.properties.virtualserver.ResourceRef -ManagementAddressOnly
                    $connections += $virtualServerMgmtAddress
                }

                return $connections
            }
            else {
                return $result
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnInfrastructureInfo {
    <#
    .SYNOPSIS
        Get the SDN infrastructure information from network controller. The function will update the $Global:SdnDiagnostics.EnvironmentInfo variable.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER Credential
		Specifies a user account that has permission to Network Controller. The default is the current user.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API. Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
		Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    .PARAMETER Force
        Switch parameter to force a refresh of the environment cache details
    .EXAMPLE
        PS> Get-SdnInfrastructureInfo
    .EXAMPLE
        PS> Get-SdnInfrastructureInfo -NetworkController 'NC01' -Credential (Get-Credential) -NcRestCredential (Get-Credential)
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $false)]
        [String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [ValidateScript({
            if ($_.Scheme -ne "http" -and $_.Scheme -ne "https") {
                throw New-Object System.FormatException("Parameter is expected to be in http:// or https:// format.")
            }
            return $true
        })]
        [Uri]$NcUri,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [Switch]$Force
    )

    if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
        Confirm-IsNetworkController
    }

    $restParams = @{
        NcUri       = $null
        ErrorAction = 'Continue'
    }
    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $restParams.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $restParams.Add('NcRestCredential', $NcRestCredential)
        }
    }

    try {
        # if force is defined, purge the cache to force a refresh on the objects
        if ($PSBoundParameters.ContainsKey('Force')) {
            $Global:SdnDiagnostics.EnvironmentInfo.NcUrl = $null
            $global:SdnDiagnostics.EnvironmentInfo.NetworkController = $null
            $global:SdnDiagnostics.EnvironmentInfo.LoadBalancerMux = $null
            $Global:SdnDiagnostics.EnvironmentInfo.Gateway = $null
            $Global:SdnDiagnostics.EnvironmentInfo.Server = $null
            $Global:SdnDiagnostics.EnvironmentInfo.FabricNodes = $null
        }

        # get cluster type
        $clusterType = Get-SdnClusterType -NetworkController $NetworkController -Credential $Credential
        if ($clusterType) {
            $Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType = $clusterType
        }

        # get the cluster name if we using a failover cluster
        if ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType -eq 'FailoverCluster') {
            if ([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.EnvironmentInfo.FailoverClusterConfig.Name)) {
                $Global:SdnDiagnostics.EnvironmentInfo.FailoverClusterConfig.Name = Get-SdnClusterName -NetworkController $NetworkController -Credential $Credential
            }
        }

        # get the NC Northbound API endpoint
        if ($NcUri) {
            $Global:SdnDiagnostics.EnvironmentInfo.NcUrl = $NcUri.AbsoluteUri
        }
        elseif ([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.EnvironmentInfo.NcUrl)) {
            $result = Get-SdnNetworkControllerRestURL -NetworkController $NetworkController -Credential $Credential
            if ([string]::IsNullOrEmpty($result)) {
                throw New-Object System.NullReferenceException("Unable to locate REST API endpoint for Network Controller. Please specify REST API with -RestUri parameter.")
            }

            $Global:SdnDiagnostics.EnvironmentInfo.NcUrl = $result
        }

        $restParams.NcUri = $Global:SdnDiagnostics.EnvironmentInfo.NcUrl

        # get the supported rest API versions from network controller
        # as we default this to v1 on module import within $Global.SdnDiagnostics, will not check to see if null first
        $currentRestVersion = (Get-SdnDiscovery @restParams).properties.currentRestVersion
        if (-NOT [String]::IsNullOrEmpty($currentRestVersion)) {
            $Global:SdnDiagnostics.EnvironmentInfo.RestApiVersion = $currentRestVersion
        }

        # get the network controllers
        if ([System.String]::IsNullOrEmpty($global:SdnDiagnostics.EnvironmentInfo.NetworkController)) {
            [System.Array]$global:SdnDiagnostics.EnvironmentInfo.NetworkController = Get-SdnNetworkControllerNode -NetworkController $NetworkController -ServerNameOnly -Credential $Credential -ErrorAction Continue
        }

        # get the load balancer muxes
        if ([System.String]::IsNullOrEmpty($global:SdnDiagnostics.EnvironmentInfo.LoadBalancerMux)) {
            [System.Array]$global:SdnDiagnostics.EnvironmentInfo.LoadBalancerMux = Get-SdnLoadBalancerMux @restParams -ManagementAddressOnly
        }

        # get the gateways
        if ([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.EnvironmentInfo.Gateway)) {
            [System.Array]$Global:SdnDiagnostics.EnvironmentInfo.Gateway = Get-SdnGateway @restParams -ManagementAddressOnly
        }

        # get the hypervisor hosts
        if ([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.EnvironmentInfo.Server)) {
            [System.Array]$Global:SdnDiagnostics.EnvironmentInfo.Server = Get-SdnServer @restParams -ManagementAddressOnly
        }

        # populate the global cache that contains the names of the nodes for the roles defined above
        $fabricNodes = @()
        $fabricNodes += $global:SdnDiagnostics.EnvironmentInfo.NetworkController

        if($null -ne $Global:SdnDiagnostics.EnvironmentInfo.Server){
            $fabricNodes += $Global:SdnDiagnostics.EnvironmentInfo.Server
        }

        if($null -ne $Global:SdnDiagnostics.EnvironmentInfo.Gateway){
            $fabricNodes += $Global:SdnDiagnostics.EnvironmentInfo.Gateway
        }

        if($null -ne $Global:SdnDiagnostics.EnvironmentInfo.LoadBalancerMux){
            $fabricNodes += $Global:SdnDiagnostics.EnvironmentInfo.LoadBalancerMux
        }

        $Global:SdnDiagnostics.EnvironmentInfo.FabricNodes = $fabricNodes
    }
    catch {
        # Remove any cached info in case of exception as the cached info might be incorrect
        $Global:SdnDiagnostics.EnvironmentInfo.NcUrl = $null
        $global:SdnDiagnostics.EnvironmentInfo.NetworkController = $null
        $global:SdnDiagnostics.EnvironmentInfo.LoadBalancerMux = $null
        $Global:SdnDiagnostics.EnvironmentInfo.Gateway = $null
        $Global:SdnDiagnostics.EnvironmentInfo.Server = $null
        $Global:SdnDiagnostics.EnvironmentInfo.FabricNodes = $null
        $_ | Trace-Exception
        $_ | Write-Error
    }

    return $Global:SdnDiagnostics.EnvironmentInfo
}

Set-Alias -Name "Get-SdnEnvironmentInfo" -Value "Get-SdnInfrastructureInfo" -Force

function Get-SdnInternalLoadBalancer {
    <#
    .SYNOPSIS
        Performs lookups and joins between OVSDB resources, load balancers and virtual networks to create internal load balancer object mappings
    .PARAMETER NcUri
        Specifies the Network Controller URI to connect to.
    .PARAMETER IPAddress
        Specify the private IP address of the Internal Load Balancer.
    .PARAMETER ProviderAddress
        Specify the provider address IP that is associated with the Internal Load Balancer.
    .PARAMETER Credential
        Specifies a user account that has permission to the Hyper-V Hosts within the SDN Fabric. The default is the current user.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    .EXAMPLE
        Get-SdnInternalLoadBalancer -NcUri https://nc.contoso.com -IPAddress 10.10.0.50
    .EXAMPLE
        Get-SdnInternalLoadBalancer -NcUri https://nc.contoso.com -NcRestCredential (Get-Credential)
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $true, ParameterSetName = 'IPAddress')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ProviderAddress')]
        [Uri]$NcUri,

        [Parameter(Mandatory = $true, ParameterSetName = 'IPAddress')]
        [IPAddress]$IPAddress,

        [Parameter(Mandatory = $true, ParameterSetName = 'ProviderAddress')]
        [IPAddress]$ProviderAddress,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'IPAddress')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ProviderAddress')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'IPAddress')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ProviderAddress')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'IPAddress')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ProviderAddress')]
        [X509Certificate]$NcRestCertificate
    )

    $array = @()
    $subnetHash = [System.Collections.Hashtable]::new()
    $frontendHash = [System.Collections.Hashtable]::new()

    $ncRestParams = @{
        NcUri = $NcUri
    }
    if ($PSBoundParameters.ContainsKey('NcRestCertificate')) {
        $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
    }
    else {
        $ncRestParams.Add('NcRestCredential', $NcRestCredential)
    }

    try {
        $servers = Get-SdnServer @ncRestParams -ManagementAddressOnly

        # if this returns null, this is due to no tenant internal load balancers have been provisioned on the system
        # in which case all the further processing is not needed
        $ovsdbAddressMappings = Get-SdnOvsdbAddressMapping -ComputerName $servers -Credential $Credential | Where-Object {$_.mappingType -eq 'learning_disabled'}
        if($null -eq $ovsdbAddressMappings){
            return $null
        }

        "Located {0} address mappings from OVSDB" -f $ovsdbAddressMappings.Count | Trace-Output -Level:Verbose
        # create a hash table based on the subnet instanceId contained within the virtual networks
        $virtualNetworks = Get-SdnResource @ncRestParams -Resource VirtualNetworks
        foreach($group in $virtualNetworks.properties.subnets | Group-Object InstanceID){
            [void]$subnetHash.Add($group.Name, $group.Group)
        }

        "Located {0} subnets" -f $subnetHash.Count | Trace-Output -Level:Verbose
        # create a hash table based on the resourceRef of the frontendIPConfigurations within the load balancers
        $loadBalancers = Get-SdnResource @ncRestParams -Resource LoadBalancers
        foreach($group in $loadBalancers.properties.frontendIPConfigurations | Group-Object resourceRef){
            [void]$frontendHash.Add($group.Name, $group.Group)
        }

        "Located {0} frontendIPConfigurations" -f $frontendHash.Count | Trace-Output -Level:Verbose
        foreach($ovsdbObject in $ovsdbAddressMappings){

            # leveraging the routing domain ID taken from the OVSDB objects we need to
            # do a lookup against the virtual network subnets to locate the associated ip configurations
            # once we have the ipconfiguration, we want to enumerate each load balancer to match on the customer ip address
            $tenantSubnet = $subnetHash[$ovsdbObject.RoutingDomainID.Guid]
            if($tenantSubnet){
                $loadBalancerResourceRef = $tenantSubnet.properties.ipConfigurations | Where-Object {$_.ResourceRef -like "/loadBalancers/*"}
                if($loadBalancerResourceRef){
                    foreach($resource in $loadBalancerResourceRef){
                        $internalLoadBalancer = $frontendHash[$resource.resourceRef]

                        # if the customer ip address does not match between load balancer and ovsdb then skip it as
                        # this is not the load balancer you are looking for
                        if($internalLoadBalancer){
                            if($internalLoadBalancer.properties.privateIPAddress -ne $ovsdbObject.CustomerAddress){
                                continue
                            }

                            # create a new object to add to the array list as we now have all the mappings we want
                            $array += [PSCustomObject]@{
                                ResourceRef = [String]$internalLoadBalancer.resourceRef
                                CustomerAddress = [IPAddress]$internalLoadBalancer.properties.privateIPAddress
                                ProviderAddress = [IPAddress]$ovsdbObject.ProviderAddress
                            }
                        }
                        else {
                            "Unable to locate Load Balancer Frontend IP Configuration for {0}" -f $resource.resourceRef | Trace-Output -Level:Warning
                        }
                    }
                }
                else {
                    "Unable to locate any Load Balancer objects within IP configurations for {0}" -f $tenantSubnet.resourceRef  | Trace-Output -Level:Warning
                }
            }
            else {
                "Unable to locate Virtual Network Subnet related to Routing Domain ID {0}" -f $ovsdbObject.RoutingDomainID | Trace-Output -Level:Warning
            }
        }

        if ($IPAddress) {
            return ($array | Where-Object {$_.CustomerAddress -eq $IPAddress})
        }

        if ($ProviderAddress) {
            return ($array | Where-Object {$_.ProviderAddress -eq $ProviderAddress})
        }

        return ($array | Sort-Object CustomerAddress -Unique)
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnLoadBalancerMux {
    <#
    .SYNOPSIS
        Returns a list of load balancer muxes from network controller
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER ResourceId
        Specifies the unique identifier for the resource.
    .PARAMETER ResourceRef
        Specifies the resource reference for the resource.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    .PARAMETER ManagementAddressOnly
        Optional parameter to only return back the Management Address value.
    .EXAMPLE
        PS> Get-SdnLoadBalancerMux -NcUri 'https://NC.FQDN' -NcRestCredential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnLoadBalancerMux -NcUri 'https://NC.FQDN' -NcRestCredential (Get-Credential) -ManagementAddressOnly
    .EXAMPLE
        PS> Get-SdnLoadBalancerMux -NcUri 'https://NC.FQDN' -NcRestCredential (Get-Credential) -ResourceId 'f5e3b3e0-1b7a-4b9e-8b9e-5b5e3b3e0f5e'
    .EXAMPLE
        PS> Get-SdnLoadBalancerMux -NcUri 'https://NC.FQDN' -NcRestCredential (Get-Credential) -ResourceRef '/LoadBalancerMuxes/f5e3b3e0-1b7a-4b9e-8b9e-5b5e3b3e0f5e'
    .EXAMPLE
        PS> Get-SdnLoadBalancerMux -NcUri 'https://NC.FQDN' -NcRestCredential (Get-Credential) -ResourceId 'f5e3b3e0-1b7a-4b9e-8b9e-5b5e3b3e0f5e' -ManagementAddressOnly
    .EXAMPLE
        PS> Get-SdnLoadBalancerMux -NcUri 'https://NC.FQDN' -NcRestCredential (Get-Credential) -ResourceRef '/LoadBalancerMuxes/f5e3b3e0-1b7a-4b9e-8b9e-5b5e3b3e0f5e' -ManagementAddressOnly
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceId')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceRef')]
        [Uri]$NcUri,

        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceId')]
        [String]$ResourceId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceRef')]
        [String]$ResourceRef,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceId')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [X509Certificate]$NcRestCertificate,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceId')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceId')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [switch]$ManagementAddressOnly
    )

    $ncRestParams = @{
        NcUri = $NcUri
    }
    if ($PSBoundParameters.ContainsKey('NcRestCertificate')) {
        $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
    }
    else {
        $ncRestParams.Add('NcRestCredential', $NcRestCredential)
    }

    try {
        switch ($PSCmdlet.ParameterSetName) {
            'ResourceId' {
                $result = Get-SdnResource @ncRestParams -Resource 'LoadBalancerMuxes' -ResourceId $ResourceId
            }
            'ResourceRef' {
                $result = Get-SdnResource @ncRestParams -ResourceRef $ResourceRef
            }
            default {
                $result = Get-SdnResource @ncRestParams -Resource 'LoadBalancerMuxes'
            }
        }

        if ($result) {
            foreach($obj in $result){
                if($obj.properties.provisioningState -ne 'Succeeded'){
                    "{0} is reporting provisioningState: {1}" -f $obj.resourceId, $obj.properties.provisioningState | Trace-Output -Level:Warning
                }
            }

            if($ManagementAddressOnly){
                $connections = @()
                foreach ($resource in $result) {
                    $virtualServerMgmtAddress = Get-SdnVirtualServer @ncRestParams -ResourceRef $resource.properties.virtualserver.ResourceRef -ManagementAddressOnly
                    $connections += $virtualServerMgmtAddress
                }

                return $connections
            }
            else {
                return $result
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnNetworkController {
    <#
    .SYNOPSIS
        Gets network controller application settings from the network controller.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnNetworkController
    .EXAMPLE
        PS> Get-SdnNetworkController -NetworkController 'NC01' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    switch ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType) {
        'FailoverCluster' {
            Get-SdnNetworkControllerFC @PSBoundParameters
        }
        'ServiceFabric' {
            Get-SdnNetworkControllerSF @PSBoundParameters
        }
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

    switch ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType) {
        'FailoverCluster' {
            Get-SdnNetworkControllerFCClusterInfo @PSBoundParameters
        }
        'ServiceFabric' {
            Get-SdnNetworkControllerSFClusterInfo @PSBoundParameters
        }
    }
}

function Get-SdnNetworkControllerNode {
    <#
    .SYNOPSIS
        Returns a list of servers from network controller.
    .PARAMETER Name
        Specifies the friendly name of the node for the network controller. If not provided, settings are retrieved for all nodes in the deployment.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
	.PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnNetworkControllerNode
    .EXAMPLE
        PS> Get-SdnNetworkControllerNode -NetworkController 'NC01' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$Name,

        [Parameter(Mandatory = $false)]
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [switch]$ServerNameOnly
    )

    switch ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType) {
        'FailoverCluster' {
            Get-SdnNetworkControllerFCNode @PSBoundParameters
        }
        'ServiceFabric' {
            Get-SdnNetworkControllerSFNode @PSBoundParameters
        }
    }
}

function Get-SdnNetworkControllerNodeCertificate {
    <#
    .SYNOPSIS
        Returns the current Network Controller node certificate
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    if ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType -ine 'ServiceFabric') {
        throw New-Object System.NotSupportedException("This function is only supported on Service Fabric clusters.")
    }

    Confirm-IsNetworkController

    try {
        $networkControllerNode = Get-SdnNetworkControllerSFNode -Name $env:ComputerName -Credential $Credential

        # check to see if FindCertificateBy property exists as this was added in later builds
        # else if does not exist, default to Thumbprint for certificate
        if ($null -ne $networkControllerNode.FindCertificateBy) {
            "Network Controller is currently configured for FindCertificateBy: {0}" -f $networkControllerNode.FindCertificateBy | Trace-Output -Level:Verbose
            switch ($networkControllerNode.FindCertificateBy) {
                'FindBySubjectName' {
                    "`tFindBySubjectName: {0}" -f $networkControllerNode.NodeCertSubjectName | Trace-Output -Level:Verbose
                    $certificate = Get-SdnCertificate -Path 'Cert:\LocalMachine\My' -Subject "CN=$($networkControllerNode.NodeCertSubjectName)"
                }

                'FindByThumbprint' {
                    "`FindByThumbprint: {0}" -f $networkControllerNode.NodeCertificateThumbprint | Trace-Output -Level:Verbose
                    $certificate = Get-SdnCertificate -Path 'Cert:\LocalMachine\My' -Thumbprint $networkControllerNode.NodeCertificateThumbprint
                }
            }
        }
        else {
            $certificate = Get-SdnCertificate -Path 'Cert:\LocalMachine\My' -Thumbprint $networkControllerNode.NodeCertificateThumbprint
        }

        if ($null -eq $certificate) {
            throw New-Object System.NullReferenceException("Unable to locate Network Controller Certificate")
        }

        return $certificate
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnNetworkControllerRestCertificate {
    <#
    .SYNOPSIS
        Returns the current Network Controller REST Certificate
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    if ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType -ine 'ServiceFabric') {
        throw New-Object System.NotSupportedException("This function is only supported on Service Fabric clusters.")
    }

    Confirm-IsNetworkController

    try {
        $networkController = Get-SdnNetworkControllerSF -NetworkController $env:COMPUTERNAME -Credential $Credential
        $ncRestCertThumprint = $($networkController.ServerCertificate.Thumbprint).ToString()
        $certificate = Get-SdnCertificate -Path 'Cert:\LocalMachine\My' -Thumbprint $ncRestCertThumprint

        if ($null -eq $certificate) {
            throw New-Object System.NullReferenceException("Unable to locate Network Controller Rest Certificate")
        }

        return $certificate
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnNetworkControllerState {
    <#
    .SYNOPSIS
        Gathers the Network Controller State dump files (IMOS) from each of the Network Controllers
    .PARAMETER NetworkController
        The computer name of the Network Controller used to retrieve Infrastructure Info and trigger IMOS generation.
    .PARAMETER OutputDirectory
        Directory location to save results. By default it will create a new sub-folder called NetworkControllerState that the files will be copied to
	.PARAMETER Credential
		Specifies a user account that has permission to Network Controller. The default is the current user.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    .PARAMETER ExecutionTimeout
        Specify the execution timeout (seconds) on how long you want to wait for operation to complete before cancelling operation. If omitted, defaults to 300 seconds.
    .EXAMPLE
        PS> Get-SdnNetworkControllerState -NetworkController 'Contoso-NC01' -OutputDirectory "C:\Temp\CSS_SDN"
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$NetworkController,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate,

        [Parameter(Mandatory = $false)]
        [int]$ExecutionTimeOut = 300
    )

    $ncRestParams = @{
        NcUri = $null
    }
    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $restCredParam = @{ NcRestCertificate = $NcRestCertificate }
            $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $restCredParam = @{ NcRestCredential = $NcRestCredential }
            $ncRestParams.Add('NcRestCredential', $NcRestCredential)
        }
    }

    try {
        "Collecting In Memory Object State (IMOS) for Network Controller" | Trace-Output
        $config = Get-SdnModuleConfiguration -Role:NetworkController
        [System.IO.FileInfo]$netControllerStatePath = $config.properties.netControllerStatePath
        [System.IO.FileInfo]$outputDir = Join-Path -Path $OutputDirectory.FullName -ChildPath 'NetworkControllerState'

        if (!(Test-Path -Path $outputDir.FullName -PathType Container)) {
            $null = New-Item -Path $outputDir.FullName -ItemType Directory -Force
        }

        $scriptBlock = {
            param([Parameter(Position = 0)][String]$param1)
            try {
                if (Test-Path -Path $param1 -PathType Container) {
                    Get-Item -Path $param1 | Remove-Item -Recurse -Confirm:$false -Force -ErrorAction SilentlyContinue
                }

                $null = New-Item -Path $param1 -ItemType Container -Force
            }
            catch {
                $_ | Write-Error
            }
        }

        $infraInfo = Get-SdnInfrastructureInfo -NetworkController $NetworkController -Credential $Credential @restCredParam
        $ncRestParams.NcUri = $infraInfo.NcUrl

        # invoke scriptblock to clean up any stale NetworkControllerState files
        Invoke-PSRemoteCommand -ComputerName $infraInfo.NetworkController -Credential $Credential -ScriptBlock $scriptBlock -ArgumentList $netControllerStatePath.FullName

        # invoke the call to generate the files
        # once the operation completes and returns true, then enumerate through the Network Controllers defined to collect the files
        $result = Invoke-SdnNetworkControllerStateDump @ncRestParams -ExecutionTimeOut $ExecutionTimeOut
        if ($result) {
            foreach ($ncVM in $infraInfo.NetworkController) {
                Copy-FileFromRemoteComputer -Path "$($config.properties.netControllerStatePath)\*" -ComputerName $ncVM -Destination $outputDir.FullName
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnNetworkInterfaceOutboundPublicIPAddress {
    <#
    .SYNOPSIS
        Gets the outbound public IP address that is used by a network interface.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER ResourceId
        Specifies the unique identifier for the networkinterface resource.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    .EXAMPLE
        PS> Get-SdnNetworkInterfaceOutboundPublicIPAddress -NcUri "https://nc.contoso.com" -ResourceId '8f9faf0a-837b-43cd-b4bf-dbe996993514'
    .EXAMPLE
        PS> Get-SdnNetworkInterfaceOutboundPublicIPAddress -NcUri "https://nc.contoso.com" -ResourceId '8f9faf0a-837b-43cd-b4bf-dbe996993514' -Credential (Get-Credential)
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [uri]$NcUri,

        [Parameter(Mandatory = $true)]
        [System.String]$ResourceId,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate
    )

    $arrayList = [System.Collections.ArrayList]::new()

    $ncRestParams = @{
        NcUri = $NcUri
    }
    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $ncRestParams.Add('NcRestCredential', $NcRestCredential)
        }
    }

    try {
        $networkInterface = Get-SdnResource @ncRestParams -Resource:NetworkInterfaces | Where-Object { $_.resourceId -ieq $ResourceId }
        if ($null -eq $networkInterface) {
            throw New-Object System.NullReferenceException("Unable to locate network interface within Network Controller")
        }

        foreach ($ipConfig in $networkInterface.properties.ipConfigurations) {
            $publicIpRef = Get-PublicIpReference @ncRestParams -IpConfiguration $ipConfig
            if ($publicIpRef) {
                $publicIpAddress = Get-SdnResource @ncRestParams -ResourceRef $publicIpRef
                if ($publicIpAddress) {
                    [void]$arrayList.Add(
                        [PSCustomObject]@{
                            IPConfigResourceRef      = $ipConfig.resourceRef
                            IPConfigPrivateIPAddress = $ipConfig.properties.privateIPAddress
                            PublicIPResourceRef      = $publicIpAddress.resourceRef
                            PublicIPAddress          = $publicIpAddress.properties.ipAddress
                        }
                    )
                }
            }
        }

        return $arrayList
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnPublicIPPoolUsageSummary {
    <#
    .SYNOPSIS
        Returns back the IP addresses associated with the public logical subnet IP pools within the Network Controller environment.
    .DESCRIPTION
        This function returns back a list of IP addresses that are consumed by the PublicIPAddresses and LoadBalancer resources that are derived from the public IP pools.
        This helps operators quickly locate which resources are associated with a public IP address, in addition to identify available vs non-available IP addresses.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate
    )

    $array = @()
    $ncRestParams = @{
        NcUri = $NcUri
    }
    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $ncRestParams.Add('NcRestCredential', $NcRestCredential)
        }
    }

    try {
        $logicalNetworks = Get-SdnResource -Resource LogicalNetworks @ncRestParams | Where-Object {$_.properties.subnets.properties.isPublic -ieq $true}
        $loadBalancers = Get-SdnResource -Resource LoadBalancers @ncRestParams
        $publicIpAddresses = Get-SdnResource -Resource PublicIPAddresses @ncRestParams

        foreach ($subnet in $logicalNetworks.properties.subnets) {
            foreach ($ipPool in $subnet.properties.ipPools) {
                # check to see if there was any loadbalancer frontend resources on the system and cross compare with the logical subnet ipPool
                # if they address falls within the ipPool range, then add to the array
                if ($loadBalancers) {
                    foreach ($loadBalancer in $loadBalancers) {
                        foreach ($frontEndConfig in $loadBalancer.properties.frontendIPConfigurations) {
                            if ($frontEndConfig.properties.privateIPAddress) {
                                if (Confirm-IpAddressInRange -IpAddress $frontEndConfig.properties.privateIPAddress -StartAddress $ipPool.properties.startIpAddress -EndAddress $ipPool.properties.EndIpAddress) {

                                    $object = [PSCustomObject]@{
                                        IPPool = $ipPool.ResourceId
                                        IPAddress = $frontEndConfig.properties.privateIPAddress
                                        ProvisioningState = $frontEndConfig.properties.provisioningState
                                        AllocationMethod = $frontEndConfig.properties.privateIPAllocationMethod
                                        ResourceType = 'FrontEndIpConfiguration'
                                        ResourceId = $frontEndConfig.resourceId
                                        InstanceId = $frontEndConfig.instanceId
                                        AssociatedResource = $loadBalancer.resourceRef
                                    }

                                    $array += $object
                                }
                            }
                        }
                    }
                }

                # check to see if there was any public IP address resources on the system and cross compare with the logical subnet ipPool
                # if they address falls within the ipPool range, then add to the array
                if ($publicIpAddresses) {
                    foreach ($publicIp in $publicIpAddresses) {
                        if (Confirm-IpAddressInRange -IpAddress $publicIp.properties.IpAddress -StartAddress $ipPool.properties.startIpAddress -EndAddress $ipPool.properties.EndIpAddress) {

                            $object = [PSCustomObject]@{
                                IPPool = $ipPool.ResourceId
                                IPAddress = $publicIp.properties.ipAddress
                                ProvisioningState = $publicIp.properties.provisioningState
                                AllocationMethod = $publicIp.properties.publicIPAllocationMethod
                                ResourceType = 'PublicIpAddress'
                                ResourceId = $publicIp.resourceId
                                InstanceId = $publicIp.instanceId
                                AssociatedResource = $publicIp.properties.ipConfiguration.resourceRef
                            }

                            $array += $object
                        }
                    }
                }
            }
        }

        return ($array | Sort-Object -Property 'IpAddress')
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnResource {
    <#
    .SYNOPSIS
        Invokes a web request to SDN API for the requested resource.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER ResourceRef
        The resource ref of the object you want to perform the operation against.
    .PARAMETER Resource
        The resource type you want to perform the operation against.
    .PARAMETER ResourceId
        Specify the unique ID of the resource.
    .PARAMETER InstanceID
        Specify the unique Instance ID of the resource.
    .PARAMETER ConvertToJson
        Convert the output to JSON format.
    .PARAMETER ApiVersion
        The API version to use when invoking against the NC REST API endpoint.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    .EXAMPLE
        PS> Get-SdnResource -NcUri "https://nc.$env:USERDNSDOMAIN" -Resource PublicIPAddresses
    .EXAMPLE
        PS> Get-SdnResource -NcUri "https://nc.$env:USERDNSDOMAIN" -Resource PublicIPAddresses -ResourceId "d9266251-a3ba-4ac5-859e-2c3a7c70352a"
    .EXAMPLE
        PS> Get-SdnResource -NcUri "https://nc.$env:USERDNSDOMAIN" -ResourceRef "/publicIPAddresses/d9266251-a3ba-4ac5-859e-2c3a7c70352a"
    .EXAMPLE
        PS> Get-SdnResource -NcUri "https://nc.$env:USERDNSDOMAIN" -ResourceRef "/publicIPAddresses/d9266251-a3ba-4ac5-859e-2c3a7c70352a" -NcRestCredential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceRef')]
        [System.String]$ResourceRef,

        [Parameter(Mandatory = $true, ParameterSetName = 'Resource')]
        [SdnApiResource]$Resource,

        [Parameter(Mandatory = $false, ParameterSetName = 'Resource')]
        [System.String]$ResourceId,

        [Parameter(Mandatory = $true, ParameterSetName = 'InstanceID')]
        [System.String]$InstanceId,

        [Parameter(Mandatory = $false)]
        [Switch]$ConvertToJson,

        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Resource')]
        [System.String]$ApiVersion = $Global:SdnDiagnostics.EnvironmentInfo.RestApiVersion,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [X509Certificate]$NcRestCertificate
    )

    $restParams = @{
        UseBasicParsing = $true
        ErrorAction     = 'Stop'
        Method          = 'Get'
    }

    if ($PSBoundParameters.ContainsKey('NcRestCertificate')) {
        $restParams.Add('Certificate', $NcRestCertificate)
    }
    else {
        $restParams.Add('Credential', $NcRestCredential)
    }

    switch ($PSCmdlet.ParameterSetName) {
        'InstanceId' {
            [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri -ApiVersion $ApiVersion -ResourceName 'internalResourceInstances'
            [System.String]$uri = "{0}/{1}" -f $uri, $InstanceId.Trim()
        }
        'ResourceRef' {
            [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri -ApiVersion $ApiVersion -ResourceRef $ResourceRef
        }
        'Resource' {
            [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri -ApiVersion $ApiVersion -ResourceName $Resource

            if ($ResourceID) {
                [System.String]$uri = "{0}/{1}" -f $uri, $ResourceId.Trim()
            }
        }
    }

    "{0} {1}" -f $method, $uri | Trace-Output -Level:Verbose
    $restParams.Add('Uri', $uri)

    # gracefully handle System.Net.WebException responses such as 404 to throw warning
    # anything else we want to throw terminating exception and capture for debugging purposes
    try {
        $result = Invoke-RestMethodWithRetry @restParams
    }
    catch [System.Net.WebException] {
        if ($_.Exception.Response.StatusCode -eq 'NotFound') {
            "{0} ({1})" -f $_.Exception.Message, $_.Exception.Response.ResponseUri.AbsoluteUri | Write-Warning
            return $null
        }
        else {
            throw $_
        }
    }

    # if multiple objects are returned, they will be nested under a property called value
    # so we want to do some manual work here to ensure we have a consistent behavior on data returned back
    if ($result.value) {
        $result = $result.value
    }

    # in some instances if the API returns empty object, we will see it saved as 'nextLink' which is a empty string property
    # we need to return null instead otherwise the empty string will cause calling functions to treat the value as it contains data
    elseif ($result.PSObject.Properties.Name -ieq "nextLink" -and $result.PSObject.Properties.Name.Count -eq 1) {
        return $null
    }

    if ($ConvertToJson) {
        return ($result | ConvertTo-Json -Depth 10)
    }
    else {
        return $result
    }
}

function Get-SdnServer {
    <#
    .SYNOPSIS
        Returns a list of servers from network controller.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER ResourceId
        Specifies the unique identifier for the resource.
    .PARAMETER ResourceRef
        Specifies the resource reference for the resource.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    .PARAMETER ManagementAddressOnly
        Optional parameter to only return back the Management Address value.
    .EXAMPLE
        PS> Get-SdnServer -NcUri 'https://NC.FQDN' -NcRestCredential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnServer -NcUri 'https://NC.FQDN' -NcRestCredential (Get-Credential) -ManagementAddressOnly
    .EXAMPLE
        PS> Get-SdnServer -NcUri 'https://NC.FQDN' -NcRestCredential (Get-Credential) -ResourceId 'f5e3b3e0-1b7a-4b9e-8b9e-5b5e3b3e0f5e'
    .EXAMPLE
        PS> Get-SdnServer -NcUri 'https://NC.FQDN' -NcRestCredential (Get-Credential) -ResourceRef 'Servers/f5e3b3e0-1b7a-4b9e-8b9e-5b5e3b3e0f5e'
    .EXAMPLE
        PS> Get-SdnServer -NcUri 'https://NC.FQDN' -NcRestCredential (Get-Credential) -ResourceId 'f5e3b3e0-1b7a-4b9e-8b9e-5b5e3b3e0f5e' -ManagementAddressOnly
    .EXAMPLE
        PS> Get-SdnServer -NcUri 'https://NC.FQDN' -NcRestCredential (Get-Credential) -ResourceRef 'Servers/f5e3b3e0-1b7a-4b9e-8b9e-5b5e3b3e0f5e' -ManagementAddressOnly
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceId')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceRef')]
        [Uri]$NcUri,

        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceId')]
        [String]$ResourceId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceRef')]
        [String]$ResourceRef,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceId')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [X509Certificate]$NcRestCertificate,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceId')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceId')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [switch]$ManagementAddressOnly
    )

    $ncRestParams = @{
        NcUri = $NcUri
    }
    if ($PSBoundParameters.ContainsKey('NcRestCertificate')) {
        $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
    }
    else {
        $ncRestParams.Add('NcRestCredential', $NcRestCredential)
    }

    try {
        switch ($PSCmdlet.ParameterSetName) {
            'ResourceId' {
                $result = Get-SdnResource @ncRestParams -Resource 'Servers' -ResourceId $ResourceId
            }
            'ResourceRef' {
                $result = Get-SdnResource @ncRestParams -ResourceRef $ResourceRef
            }
            default {
                $result = Get-SdnResource @ncRestParams -Resource 'Servers'
            }
        }

        if ($result) {
            foreach($obj in $result){
                if($obj.properties.provisioningState -ne 'Succeeded'){
                    "{0} is reporting provisioningState: {1}" -f $obj.resourceId, $obj.properties.provisioningState | Trace-Output -Level:Warning
                }
            }

            if($ManagementAddressOnly){
                $connections = (Get-ManagementAddress -ManagementAddress $result.properties.connections.managementAddresses)
                return $connections
            }
            else {
                return $result
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnSlbStateInformation {
    <#
    .SYNOPSIS
        Generates an aggregated report of Virtual IPs (VIPs) in the environment and their current status as reported by Software Load Balancer and MUXes.
    .PARAMETER NcUri
         Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER VirtualIPAddress
        Specifies the VIP address to return information for. If omitted, returns all VIPs.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    .PARAMETER ExecutionTimeout
        Specify the timeout duration to wait before automatically terminated. If omitted, defaults to 600 seconds.
    .PARAMETER PollingInterval
        Interval in which to query the state of the request to determine completion.
    .EXAMPLE
        Get-SdnSlbStateInformation -NcUri "https://nc.contoso.com"
    .EXAMPLE
        Get-SdnSlbStateInformation -NcUri "https://nc.contoso.com" -VirtualIPAddress 41.40.40.1
    .EXAMPLE
        Get-SdnSlbStateInformation -NcUri "https://nc.contoso.com" -NcRestCredential (Get-Credential)
    .EXAMPLE
        Get-SdnSlbStateInformation -NcUri "https://nc.contoso.com" -ExecutionTimeout 1200
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [IPAddress]$VirtualIPAddress,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate,

        [Parameter(Mandatory = $false)]
        [int]$ExecutionTimeOut = 600,

        [Parameter(Mandatory = $false)]
        [int]$PollingInterval = 5
    )

    $putParams = @{
        Uri             = $null
        Method          = 'Put'
        Headers         = @{"Accept" = "application/json" }
        Content         = "application/json; charset=UTF-8"
        Body            = "{}"
        UseBasicParsing = $true
    }

    $getParams = @{
        Uri             = $null
        UseBasicParsing = $true
    }

    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $putParams.Add('Certificate', $NcRestCertificate)
            $getParams.Add('Certificate', $NcRestCertificate)
        }
        'RestCredential' {
            $putParams.Add('Credential', $NcRestCredential)
            $getParams.Add('Credential', $NcRestCredential)
        }
    }

    try {
        $stopWatch = [system.diagnostics.stopwatch]::StartNew()

        [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri -ResourceName 'SlbState'
        "Gathering SLB state information from {0}" -f $uri | Trace-Output -Level:Verbose
        $putParams.Uri = $uri

        $putResult = Invoke-WebRequestWithRetry @putParams

        $resultObject = ConvertFrom-Json $putResult.Content
        "Response received $($putResult.Content)" | Trace-Output -Level:Verbose
        [System.String]$operationURI = Get-SdnApiEndpoint -NcUri $NcUri -ResourceName 'SlbStateResults' -OperationId $resultObject.properties.operationId
        $getParams.Uri = $operationURI

        while ($true) {
            if ($stopWatch.Elapsed.TotalSeconds -gt $ExecutionTimeOut) {
                $stopWatch.Stop()
                $msg = "Unable to get results for OperationId: {0}. Operation timed out" -f $operationId
                throw New-Object System.TimeoutException($msg)
            }

            Start-Sleep -Seconds $PollingInterval

            $stateResult = Invoke-WebRequestWithRetry @getParams
            $stateResult = $stateResult.Content | ConvertFrom-Json
            if ($stateResult.properties.provisioningState -ine 'Updating') {
                break
            }
        }

        $stopWatch.Stop()

        if ($stateResult.properties.provisioningState -ine 'Succeeded') {
            $msg = "Unable to get results for OperationId: {0}. {1}" -f $operationId, $stateResult.properties
            throw New-Object System.Exception($msg)
        }

        # if a VIP address is specified, return only the details for that VIP
        # must do some processing to get into the raw data
        if ($VirtualIPAddress) {
            $tenantDetails = $stateResult.properties.output.datagroups | Where-object { $_.name -eq 'Tenant' }
            $vipDetails = $tenantDetails.dataSections.dataunits | Where-object { $_.name -eq $VirtualIPAddress.IPAddressToString }
            return $vipDetails.value
        }

        return $stateResult.properties.output
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnVipConfig {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$VirtualIPAddress
    )

    $slbManager = Connect-SlbManager -ErrorAction Stop
    if ($slbManager) {
        $vipConfig = $slbManager.GetVipConfiguration($VirtualIPAddress)
        return $vipConfig
    }
}

function Invoke-SdnResourceDump {
    <#
    .SYNOPSIS
        Performs API request to all available northbound endpoints for NC and dumps out the resources to json file.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request. Enter a variable that contains a certificate or a command or expression that gets the certificate.
	.PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Invoke-SdnResourceDump
    .EXAMPLE
        PS> Invoke-SdnResourceDump -NcUri "https://nc.contoso.com"
    .EXAMPLE
        PS> Invoke-SdnResourceDump -NcUri "https://nc.contoso.com" -NcRestCredential (Get-Credential)
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    $params = @{
        NcUri = $NcUri
    }
    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $params.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $params.Add('NcRestCredential', $NcRestCredential)
        }
    }

    try {
        "Generating resource dump for Network Controller NB API endpoints" | Trace-Output
        [System.IO.FileInfo]$outputDir = Join-Path -Path $OutputDirectory.FullName -ChildPath 'SdnApiResources'
        if (!(Test-Path -Path $outputDir.FullName -PathType Container)) {
            $null = New-Item -Path $outputDir.FullName -ItemType Directory -Force
        }

        $apiVersion = (Get-SdnDiscovery @params).currentRestVersion
        if ($null -ieq $apiVersion) {
            $apiVersion = 'v1'
        }

        # objects returned from the apiResourse property are a hashtable, so need to work in key/value pairs
        $config = Get-SdnModuleConfiguration -Role:NetworkController
        [int]$apiVersionInt = $ApiVersion.Replace('v','').Replace('V','')
        foreach ($key in $config.properties.apiResources.Keys) {
            $value = $config.Properties.apiResources[$key]

            if ($params.ContainsKey('ResourceRef')) {
                $params.ResourceRef = $value.uri
            }
            else {
                $params.Add('ResourceRef', $value.uri)
            }

            # skip any resources that are not designed to be exported
            if ($value.includeInResourceDump -ieq $false) {
                continue
            }

            [int]$minVersionInt = $value.minVersion.Replace('v','').Replace('V','')
            if ($minVersionInt -le $apiVersionInt) {

                # because we do not know what resources are available, we need to catch any exceptions
                # that may occur when trying to get the resource
                # in events we log a warning, we just want to redirect the warning stream to null
                try {
                    $sdnResource = Get-SdnResource @params 3>$null
                }
                catch {
                    $_ | Trace-Exception
                    continue
                }

                if ($sdnResource) {

                    # parse the value if we are enumerating credentials property as we
                    # will be redacting the value to ensure we do not compromise credentials
                    if ($key -ieq 'Credentials') {
                        $sdnResource | ForEach-Object {
                            if ($_.properties.type -ieq 'UserNamePassword') {
                                $_.properties.value = "removed_for_security_reasons"
                            }
                        }
                    }

                    $sdnResource | Export-ObjectToFile -FilePath $outputDir.FullName -Name $key -FileType json -Depth 10
                }
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function New-SdnNetworkControllerNodeCertificate {
    <#
    .SYNOPSIS
        Generate new Self-Signed Certificate to be used by Network Controller node.
    .PARAMETER NotAfter
        Specifies the date and time, as a DateTime object, that the certificate expires. To obtain a DateTime object, use the Get-Date cmdlet. The default value for this parameter is one year after the certificate was created.
    .PARAMETER CertPassword
        Specifies the password for the exported PFX file in the form of a secure string.
    .PARAMETER Credential
    .EXAMPLE
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [datetime]$NotAfter = (Get-Date).AddYears(1),

        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$CertPassword,

        [Parameter(Mandatory = $false)]
        [System.String]$Path = "$(Get-WorkingDirectory)\Cert_{0}" -f (Get-FormattedDateTimeUTC),

        [Parameter(Mandatory = $false)]
        [System.Object]$FabricDetails,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $config = Get-SdnModuleConfiguration -Role 'NetworkController'
    $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
    if (-NOT ($confirmFeatures)) {
        throw New-Object System.NotSupportedException("The current machine is not a NetworkController, run this on NetworkController.")
    }

    if ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType -ine 'ServiceFabric') {
        throw New-Object System.NotSupportedException("This function is only supported on Service Fabric clusters.")
    }

    # ensure that the module is running as local administrator
    Confirm-IsAdmin

    try {
        if ($null -eq $FabricDetails) {
            $FabricDetails = [SdnFabricInfrastructure]@{
                NetworkController = (Get-SdnNetworkControllerSFNode).Server
            }
        }

        if (-NOT (Test-Path -Path $Path -PathType Container)) {
            "Creating directory {0}" -f $Path | Trace-Output
            $CertPath = New-Item -Path $Path -ItemType Directory -Force
        }
        else {
            $CertPath = Get-Item -Path $Path
        }

        # if we return multiple certificates, we want to select the first one as the subject should be the same
        $nodeCertSubject = (Get-SdnNetworkControllerNodeCertificate)[0].Subject
        $certificate = New-SdnSelfSignedCertificate -Subject $nodeCertSubject -NotAfter $NotAfter

        # after the certificate has been generated, we want to export the certificate using the $CertPassword provided by the operator
        # and save the file to directory. This allows the rest of the function to pick up these files and perform the steps as normal
        [System.String]$pfxFilePath = "$(Join-Path -Path $CertPath.FullName -ChildPath $nodeCertSubject.ToString().ToLower().Replace('.','_').Replace("=",'_').Trim()).pfx"
        "Exporting pfx certificate to {0}" -f $pfxFilePath | Trace-Output
        $exportedCertificate = Export-PfxCertificate -Cert $certificate -FilePath $pfxFilePath -Password $CertPassword -CryptoAlgorithmOption AES256_SHA256
        $null = Import-SdnCertificate -FilePath $exportedCertificate.FullName -CertStore 'Cert:\LocalMachine\Root' -CertPassword $CertPassword

        Copy-CertificateToFabric -CertFile $exportedCertificate.FullName -CertPassword $CertPassword -FabricDetails $FabricDetails `
            -NetworkControllerNodeCert -Credential $Credential

        return ([PSCustomObject]@{
            Certificate = $certificate
            FileInfo = $exportedCertificate
        })
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function New-SdnNetworkControllerRestCertificate {
    <#
    .SYNOPSIS
        Generate new Self-Signed Certificate to be used by Network Controller.
    .PARAMETER NotAfter
        Specifies the date and time, as a DateTime object, that the certificate expires. To obtain a DateTime object, use the Get-Date cmdlet. The default value for this parameter is one year after the certificate was created.
    .PARAMETER CertPassword
        Specifies the password for the imported PFX file in the form of a secure string.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$RestName,

        [Parameter(Mandatory = $false)]
        [datetime]$NotAfter = (Get-Date).AddYears(1),

        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$CertPassword,

        [Parameter(Mandatory = $false)]
        [System.String]$Path = "$(Get-WorkingDirectory)\Cert_{0}" -f (Get-FormattedDateTimeUTC),

        [Parameter(Mandatory = $false)]
        [System.Object]$FabricDetails,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    if ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType -ine 'ServiceFabric') {
        throw New-Object System.NotSupportedException("This function is only supported on Service Fabric clusters.")
    }

    $config = Get-SdnModuleConfiguration -Role 'NetworkController'
    $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
    if (-NOT ($confirmFeatures)) {
        throw New-Object System.NotSupportedException("The current machine is not a NetworkController, run this on NetworkController.")
    }

    # ensure that the module is running as local administrator
    Confirm-IsAdmin

    try {
        if ($FabricDetails) {
            if ($FabricDetails.LoadBalancerMux -or $FabricDetails.Server) {
                $installToSouthboundDevices = $true
            }
            else {
                $installToSouthboundDevices = $false
            }
        }
        else {
            $installToSouthboundDevices = $false

            $FabricDetails = [SdnFabricInfrastructure]@{
                NetworkController = (Get-SdnNetworkControllerSFNode).Server
            }
        }

        if (-NOT (Test-Path -Path $Path -PathType Container)) {
            "Creating directory {0}" -f $Path | Trace-Output
            $CertPath = New-Item -Path $Path -ItemType Directory -Force
        }
        else {
            $CertPath = Get-Item -Path $Path
        }

        [System.String]$formattedSubject = "CN={0}" -f $RestName.Trim()
        $certificate = New-SdnSelfSignedCertificate -Subject $formattedSubject -NotAfter $NotAfter

        # after the certificate has been generated, we want to export the certificate using the $CertPassword provided by the operator
        # and save the file to directory. This allows the rest of the function to pick up these files and perform the steps as normal
        [System.String]$pfxFilePath = "$(Join-Path -Path $CertPath.FullName -ChildPath $RestName.ToLower().Replace('.','_').Replace('=','_').Trim()).pfx"
        "Exporting pfx certificate to {0}" -f $pfxFilePath | Trace-Output
        $exportedCertificate = Export-PfxCertificate -Cert $certificate -FilePath $pfxFilePath -Password $CertPassword -CryptoAlgorithmOption AES256_SHA256
        $null = Import-SdnCertificate -FilePath $exportedCertificate.FullName -CertStore 'Cert:\LocalMachine\Root' -CertPassword $CertPassword

        Copy-CertificateToFabric -CertFile $exportedCertificate.FullName -CertPassword $CertPassword -FabricDetails $FabricDetails `
            -NetworkControllerRestCertificate -InstallToSouthboundDevices:$installToSouthboundDevices -Credential $Credential

        return ([PSCustomObject]@{
            Certificate = $certificate
            FileInfo = $exportedCertificate
        })
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Set-SdnResource {
    <#
    .SYNOPSIS
        Invokes a web request to SDN API for the requested resource.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER ResourceRef
        The resource ref of the object you want to perform the operation against.
    .PARAMETER Resource
        The resource type you want to perform the operation against.
    .PARAMETER ResourceId
        Specify the unique ID of the resource.
    .PARAMETER ApiVersion
        The API version to use when invoking against the NC REST API endpoint.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    .EXAMPLE
        PS> Set-SdnResource -NcUri "https://nc.$env:USERDNSDOMAIN" -ResourceRef "/networkInterfaces/contoso-nic1" -Object $object
    .EXAMPLE
        PS> Set-SdnResource -NcUri "https://nc.$env:USERDNSDOMAIN" -Resource "networkInterfaces" -ResourceId "contoso-nic1" -Object $object
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Resource')]
        [Uri]$NcUri,

        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceRef')]
        [System.String]$ResourceRef,

        [Parameter(Mandatory = $true, ParameterSetName = 'Resource')]
        [SdnApiResource]$Resource,

        [Parameter(Mandatory = $true, ParameterSetName = 'Resource')]
        [System.String]$ResourceId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Resource')]
        [System.Object]$Object,

        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Resource')]
        [System.String]$ApiVersion = $Global:SdnDiagnostics.EnvironmentInfo.RestApiVersion,

        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Resource')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Resource')]
        [X509Certificate]$NcRestCertificate
    )

    $restParams = @{
        Uri     = $null
        Method  = 'Get'
        UseBasicParsing = $true
        ErrorAction = 'Stop'
    }

    $putRestParams = @{
        Uri     = $null
        Method  = 'Put'
        UseBasicParsing = $true
        ErrorAction = 'Stop'
        Body = $null
        Headers = @{"Accept"="application/json"}
        ContentType = "application/json; charset=UTF-8"
    }

    $confirmParams = @{
        TimeoutInSec = 300
        UseBasicParsing = $true
        ErrorAction = 'Stop'
    }

    if ($PSBoundParameters.ContainsKey('NcRestCertificate')) {
        $restParams.Add('Certificate', $NcRestCertificate)
        $confirmParams.Add('NcRestCertificate', $NcRestCertificate)
    }
    else {
        $restParams.Add('Credential', $NcRestCredential)
        $confirmParams.Add('NcRestCredential', $NcRestCredential)
    }

    try {
        switch ($PSCmdlet.ParameterSetName) {
            'ResourceRef' {
                [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri -ApiVersion $ApiVersion -ResourceRef $ResourceRef
            }
            'Resource' {
                [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri -ApiVersion $ApiVersion -ResourceName $Resource
                [System.String]$uri = "{0}/{1}" -f $uri, $ResourceId.Trim()
            }
        }

        $putRestParams.Uri = $uri
        $restParams.Uri = $uri

        # perform a query against the resource to ensure it exists
        # as we only support operations against existing resources within this function
        try {
            $null = Invoke-RestMethodWithRetry @restParams
        }
        catch [System.Net.WebException] {
            if ($_.Exception.Response.StatusCode -eq "NotFound") {
                throw New-Object System.NotSupportedException("Resource was not found. Ensure the resource exists before attempting to update it.")
            }
            else {
                throw $_
            }
        }
        catch {
            throw $_
        }

        $modifiedObject = Remove-PropertiesFromObject -Object $Object -PropertiesToRemove @('ConfigurationState','ProvisioningState')
        $jsonBody = $modifiedObject | ConvertTo-Json -Depth 100
        $putRestParams.Body = $jsonBody

        if ($PSCmdlet.ShouldProcess($uri, "Invoke-RestMethod will be called with PUT to configure the properties of $($putRestParams.Uri)`n`t$jsonBody")) {
            $null = Invoke-RestMethodWithRetry @putRestParams
            if (Confirm-ProvisioningStateSucceeded -NcUri $putRestParams.Uri @confirmParams) {
                $result = Invoke-RestMethodWithRetry @restParams
                return $result
            }
        }
    }
    catch [System.Net.WebException] {
        $_ | Trace-Exception
        Write-Error "Error: $($_.ErrorDetails.Message)"
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
    finally {
        if ($streamReader) {
            $streamReader.Dispose()
        }
    }
}

function Show-SdnVipState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [IPAddress]$VirtualIPAddress,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [Switch]$Detailed
    )

    try {
        $slbManager = Connect-SlbManager -Credential $Credential -ErrorAction Stop
        if ($slbManager) {
            $consolidatedVipState = $slbManager.GetConsolidatedVipState($VirtualIPAddress, $Detailed)
            return $consolidatedVipState
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnAuditLogSetting {
    <#
    .SYNOPSIS
        Retrieves the audit log settings for the Network Controller
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate
    )

    $params = @{
        NcUri = $NcUri
    }
    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $params.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $params.Add('NcRestCredential', $NcRestCredential)
        }
    }

    $object = [PSCustomObject]@{
        Enabled = $false
        Path = $null
    }

    try {
        # verify that the environment we are on supports at least v3 API and later
        # as described in https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ncnbi/dc23b547-9ec4-4cb3-ab20-a6bfe01ddafb
        $currentRestVersion = (Get-SdnResource @params -Resource 'Discovery').properties.currentRestVersion
        [int]$currentRestVersionInt = $currentRestVersion.Replace('V','').Replace('v','').Trim()
        if ($currentRestVersionInt -ge 3) {
            # check to see that auditing has been enabled
            $auditSettingsConfig = Get-SdnResource @params -Resource 'AuditingSettingsConfig' -ApiVersion $currentRestVersion
            if (-NOT [string]::IsNullOrEmpty($auditSettingsConfig.properties.outputDirectory)) {
                $object.Enabled = $true
                $object.Path = $auditSettingsConfig.properties.outputDirectory
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }

    return $object
}
