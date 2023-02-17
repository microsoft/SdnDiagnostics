# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Import-Module "$PSScriptRoot\..\SdnDiag.Common\SdnDiag.Common.Utilities.psm1"
Import-Module "$PSScriptRoot\..\SdnDiag.Common\SdnDiag.Common.psm1"

class SdnFabricInfrastructure {
    [System.String[]]$NetworkController
    [System.String[]]$LoadBalancerMux
    [System.String[]]$Gateway
    [System.String]$NcUrl
    [System.String]$RestApiVersion
    [System.String[]]$FabricNodes
}

enum SdnRoles {
    Gateway
    NetworkController
    Server
    LoadBalancerMux
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

function Get-SdnDiscovery {
    <#
    .SYNOPSIS
        Calls to the Discovery API endpoint to determine versioning and feature details
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri.AbsoluteUri -ResourceName 'Discovery'
        $result = Invoke-RestMethodWithRetry -Uri $uri -Method GET -UseBasicParsing -Credential $Credential -ErrorAction Stop
        return $result
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnNetworkControllerInfoOffline {
    <#
    .SYNOPSIS
        Get the Network Controller Configuration from network controller cluster manifest file. The function is used to retrieve information of the network controller when cluster down.
    .PARAMETER NetworkController
        Specifies the name the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnNetworkControllerInfoOffline
    .EXAMPLE
        PS> Get-SdnNetworkControllerInfoOffline -NetworkController 'NC01' -Credential (Get-Credential)
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

    try {
        if (-NOT ($PSBoundParameters.ContainsKey('NetworkController'))) {
            $config = Get-SdnRoleConfiguration -Role 'NetworkController'
            $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
            if (-NOT ($confirmFeatures)) {
                "The current machine is not a NetworkController, run this on NetworkController or use -NetworkController parameter to specify one" | Trace-Output -Level:Warning
                return # don't throw exception, since this is a controlled scenario and we do not need stack exception tracing
            }
        }

        $clusterManifestXml = [xml](Get-SdnServiceFabricClusterManifest -NetworkController $NetworkController -Credential $Credential)
        $NodeList = $clusterManifestXml.ClusterManifest.Infrastructure.WindowsServer.NodeList.Node
        $securitySection = $clusterManifestXml.ClusterManifest.FabricSettings.Section | Where-Object Name -eq "Security"
        $ClusterCredentialType = $securitySection.Parameter | Where-Object Name -eq "ClusterCredentialType"
        $secretCertThumbprint = $clusterManifestXml.ClusterManifest.Certificates.SecretsCertificate.X509FindValue

        $ncRestName = Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock {
            $secretCert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.Thumbprint -ieq $using:secretCertThumbprint }
            if ($null -eq $secretCert) {
                return $null
            }
            else {
                return $secretCert.Subject.Replace("CN=", "")
            }
        } -Credential $Credential

        $infraInfo = [PSCustomObject]@{
            ClusterCredentialType = $ClusterCredentialType.Value
            NodeList              = $NodeList
            NcRestName            = $ncRestName
            NcRestCertThumbprint  = $secretCertThumbprint
        }

        return $infraInfo

    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnNetworkControllerRestURL {
    <#
        .SYNOPSIS
            Queries Network Controller to identify the Rest URL endpoint that can be used to query the north bound API endpoint.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$NetworkController,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        # if already populated into the cache, return the value
        if (-NOT ([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.InfrastructureInfo.NcUrl))) {
            return $Global:SdnDiagnostics.InfrastructureInfo.NcUrl
        }

        $result = Get-SdnNetworkController -NetworkController $NetworkController -Credential $Credential

        # check to see if RestName is populated and return back to the caller
        if ($result.RestName) {
            if ($result.ServerCertificate) {
                return ("https://$($result.RestName)")
            }

            return ("http://$($result.RestName)")
        }

        return $null
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnVirtualServer {
    <#
    .SYNOPSIS
        Returns virtual server of a particular resource Id from network controller.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.

    .PARAMETER ResourceRef
        Specifies Resource Ref of virtual server.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $true)]
        [String]$ResourceRef,

        [Parameter(Mandatory = $false)]
        [switch]$ManagementAddressOnly,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $result = Get-SdnResource -NcUri $NcUri.AbsoluteUri -ResourceRef $ResourceRef -Credential $Credential

        foreach ($obj in $result) {
            if ($obj.properties.provisioningState -ne 'Succeeded') {
                "{0} is reporting provisioningState: {1}" -f $obj.resourceId, $obj.properties.provisioningState | Trace-Output -Level:Warning
            }
        }

        if ($ManagementAddressOnly) {
            # there might be multiple connection endpoints to each node so we will want to only return the unique results
            # this does not handle if some duplicate connections are listed as IPAddress with another record saved as NetBIOS or FQDN
            # further processing may be required by the calling function to handle that

            return ($result.properties.connections.managementAddresses | Sort-Object -Unique)
        }
        else {
            return $result
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Invoke-SdnNetworkControllerStateDump {
    <#
    .SYNOPSIS
        Executes a PUT operation against REST API endpoint for Network Controller to trigger a IMOS dump of Network Controller services.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER ExecutionTimeout
        Specify the execution timeout (seconds) on how long you want to wait for operation to complete before cancelling operation. If omitted, defaults to 300 seconds.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [int]$ExecutionTimeOut = 300,

        [Parameter(Mandatory = $false)]
        [int]$PollingInterval = 1
    )

    try {
        $stopWatch = [system.diagnostics.stopwatch]::StartNew()
        [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri.AbsoluteUri -ResourceRef 'diagnostics/networkControllerState'

        $null = Invoke-WebRequestWithRetry -Method 'Put' -Uri $uri -Credential $Credential -Body "{}" -UseBasicParsing `
            -Headers @{"Accept" = "application/json" } -Content "application/json; charset=UTF-8"

        # monitor until the provisionState for the object is not in 'Updating' state
        while ($true) {
            Start-Sleep -Seconds $PollingInterval
            if ($stopWatch.Elapsed.TotalSeconds -gt $ExecutionTimeOut) {
                throw New-Object System.TimeoutException("Operation did not complete within the specified time limit")
            }

            $result = Get-SdnResource -NcUri $NcUri.AbsoluteUri -ResourceRef 'diagnostics/networkControllerState' -Credential $Credential
            if ($result.properties.provisioningState -ine 'Updating') {
                break
            }
        }

        $stopWatch.Stop()

        if ($result.properties.provisioningState -ine 'Succeeded') {
            $msg = "Unable to get NetworkControllerState. ProvisioningState: {0}" -f $result.properties.provisioningState
            throw New-Object System.Exception($msg)
        }

        return $true
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnApiEndpoint {
    <#
    .SYNOPSIS
        Used to construct the URI endpoint for Network Controller NB API
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER ApiVersion
        The API version to use when invoking against the NC REST API endpoint. By default, reads from $Global:SdnDiagnostics.InfrastructureInfo.RestApiVersion
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
        [System.String]$ApiVersion = $Global:SdnDiagnostics.InfrastructureInfo.RestApiVersion,

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
            $apiEndpointProperties = $Global:SdnDiagnostics.Config.NetworkController.properties.apiResources[$ResourceName]
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

function Get-SdnGateway {
    <#
    .SYNOPSIS
        Returns a list of gateways from network controller.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER ManagementAddressOnly
        Optional parameter to only return back the Management Address value.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [switch]$ManagementAddressOnly
    )

    try {
        $result = Get-SdnResource -NcUri $NcUri.AbsoluteUri -Resource:Gateways -Credential $Credential
        if ($result) {
            foreach ($obj in $result) {
                if ($obj.properties.provisioningState -ne 'Succeeded') {
                    "{0} is reporting provisioningState: {1}" -f $obj.resourceId, $obj.properties.provisioningState | Trace-Output -Level:Warning
                }
            }

            if ($ManagementAddressOnly) {
                $managementAddresses = [System.Collections.ArrayList]::new()
                foreach ($resource in $result) {
                    $virtualServerMgmtAddress = Get-SdnVirtualServer -NcUri $NcUri.AbsoluteUri -ResourceRef $resource.properties.virtualserver.ResourceRef -ManagementAddressOnly -Credential $Credential
                    [void]$managementAddresses.Add($virtualServerMgmtAddress)
                }
                return $managementAddresses
            }
            else {
                return $result
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnInfrastructureInfo {
    <#
    .SYNOPSIS
        Get the SDN infrastructure information from network controller. The function will update the $Global:SdnDiagnostics.InfrastructureInfo variable.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER NcRestCredential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER Force
        Switch parameter to force a refresh of the environment cache details
    .EXAMPLE
        PS> Get-SdnInfrastructureInfo
    .EXAMPLE
        PS> Get-SdnInfrastructureInfo -NetworkController 'NC01' -Credential (Get-Credential) -NcRestCredential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]$NetworkController = $(HostName),

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

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [Switch]$Force
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

        # if force is defined, purge the cache to force a refresh on the objects
        if ($PSBoundParameters.ContainsKey('Force')) {
            $Global:SdnDiagnostics.InfrastructureInfo.NcUrl = $null
            $global:SdnDiagnostics.InfrastructureInfo.NetworkController = $null
            $global:SdnDiagnostics.InfrastructureInfo.LoadBalancerMux = $null
            $Global:SdnDiagnostics.InfrastructureInfo.Gateway = $null
            $Global:SdnDiagnostics.InfrastructureInfo.Server = $null
            $Global:SdnDiagnostics.InfrastructureInfo.FabricNodes = $null
        }

        # get the NC Northbound API endpoint
        if ($NcUri) {
            $Global:SdnDiagnostics.InfrastructureInfo.NcUrl = $NcUri.AbsoluteUri
        }
        elseif ([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.InfrastructureInfo.NcUrl)) {
            $result = Get-SdnNetworkControllerRestURL -NetworkController $NetworkController -Credential $Credential

            if ($null -eq $result) {
                throw New-Object System.NullReferenceException("Unable to locate REST API endpoint for Network Controller. Please specify REST API with -RestUri parameter.")
            }

            $Global:SdnDiagnostics.InfrastructureInfo.NcUrl = $result
        }

        # get the supported rest API versions from network controller
        # as we default this to v1 on module import within $Global.SdnDiagnostics, will not check to see if null first
        $currentRestVersion = (Get-SdnDiscovery -NcUri $Global:SdnDiagnostics.InfrastructureInfo.NcUrl -Credential $NcRestCredential).properties.currentRestVersion
        if (-NOT [String]::IsNullOrEmpty($currentRestVersion)) {
            $Global:SdnDiagnostics.InfrastructureInfo.RestApiVersion = $currentRestVersion
        }

        # get the network controllers
        if ([System.String]::IsNullOrEmpty($global:SdnDiagnostics.InfrastructureInfo.NetworkController)) {
            [System.Array]$global:SdnDiagnostics.InfrastructureInfo.NetworkController = Get-SdnNetworkControllerNode -NetworkController $NetworkController -ServerNameOnly -Credential $Credential
        }

        # get the load balancer muxes
        if ([System.String]::IsNullOrEmpty($global:SdnDiagnostics.InfrastructureInfo.LoadBalancerMux)) {
            [System.Array]$global:SdnDiagnostics.InfrastructureInfo.LoadBalancerMux = Get-SdnLoadBalancerMux -NcUri $Global:SdnDiagnostics.InfrastructureInfo.NcUrl -ManagementAddressOnly -Credential $NcRestCredential
        }

        # get the gateways
        if ([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.InfrastructureInfo.Gateway)) {
            [System.Array]$Global:SdnDiagnostics.InfrastructureInfo.Gateway = Get-SdnGateway -NcUri $Global:SdnDiagnostics.InfrastructureInfo.NcUrl -ManagementAddressOnly -Credential $NcRestCredential
        }

        # get the hypervisor hosts
        if ([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.InfrastructureInfo.Server)) {
            [System.Array]$Global:SdnDiagnostics.InfrastructureInfo.Server = Get-SdnServer -NcUri $Global:SdnDiagnostics.InfrastructureInfo.NcUrl -ManagementAddressOnly -Credential $NcRestCredential
        }

        # populate the global cache that contains the names of the nodes for the roles defined above
        $fabricNodes = @()
        $fabricNodes += $global:SdnDiagnostics.InfrastructureInfo.NetworkController

        if ($null -ne $Global:SdnDiagnostics.InfrastructureInfo.Server) {
            $fabricNodes += $Global:SdnDiagnostics.InfrastructureInfo.Server
        }

        if ($null -ne $Global:SdnDiagnostics.InfrastructureInfo.Gateway) {
            $fabricNodes += $Global:SdnDiagnostics.InfrastructureInfo.Gateway
        }

        if ($null -ne $Global:SdnDiagnostics.InfrastructureInfo.LoadBalancerMux) {
            $fabricNodes += $Global:SdnDiagnostics.InfrastructureInfo.LoadBalancerMux
        }

        $Global:SdnDiagnostics.InfrastructureInfo.FabricNodes = $fabricNodes

        return $Global:SdnDiagnostics.InfrastructureInfo
    }
    catch {
        # Remove any cached info in case of exception as the cached info might be incorrect
        $Global:SdnDiagnostics.InfrastructureInfo.NcUrl = $null
        $global:SdnDiagnostics.InfrastructureInfo.NetworkController = $null
        $global:SdnDiagnostics.InfrastructureInfo.LoadBalancerMux = $null
        $Global:SdnDiagnostics.InfrastructureInfo.Gateway = $null
        $Global:SdnDiagnostics.InfrastructureInfo.Server = $null
        $Global:SdnDiagnostics.InfrastructureInfo.FabricNodes = $null
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnLoadBalancerMux {
    <#
    .SYNOPSIS
        Returns a list of load balancer muxes from network controller
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER ManagementAddressOnly
        Optional parameter to only return back the Management Address value.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [switch]$ManagementAddressOnly
    )

    try {
        $result = Get-SdnResource -NcUri $NcUri.AbsoluteUri -Resource:LoadBalancerMuxes -Credential $Credential
        if ($result) {
            foreach ($obj in $result) {
                if ($obj.properties.provisioningState -ne 'Succeeded') {
                    "{0} is reporting provisioningState: {1}" -f $obj.resourceId, $obj.properties.provisioningState | Trace-Output -Level:Warning
                }
            }

            if ($ManagementAddressOnly) {
                $managementAddresses = [System.Collections.ArrayList]::new()
                foreach ($resource in $result) {
                    $virtualServerMgmtAddress = Get-SdnVirtualServer -NcUri $NcUri.AbsoluteUri -ResourceRef $resource.properties.virtualserver.ResourceRef -ManagementAddressOnly -Credential $Credential
                    [void]$managementAddresses.Add($virtualServerMgmtAddress)
                }
                return $managementAddresses
            }
            else {
                return $result
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnNetworkController {
    <#
    .SYNOPSIS
        Gets network controller application settings.
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
        [System.String]$NetworkController = $(HostName),

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

        if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
            $result = Get-NetworkController
        }
        else {
            $result = Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock { Get-NetworkController } -Credential $Credential
        }

        return $result
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnNetworkControllerConfigurationState {
    <#
    .SYNOPSIS
        Outputs a set of configuration state files for the network controller role.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .EXAMPLE
        PS> Get-SdnNetworkControllerConfigurationState -OutputDirectory "C:\Temp\CSS_SDN"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    $ProgressPreference = 'SilentlyContinue'

    try {
        $config = Get-SdnRoleConfiguration -Role:NetworkController
        [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath "ConfigState"
        [System.IO.FileInfo]$ncAppDir = Join-Path $OutputDirectory.FullName -ChildPath "NCApp"
        [System.IO.FileInfo]$regDir = Join-Path -Path $OutputDirectory.FullName -ChildPath "Registry"

        "Collect configuration state details for role {0}" -f $config.Name | Trace-Output

        if (-NOT (Initialize-DataCollection -Role NetworkController -FilePath $OutputDirectory.FullName -MinimumMB 100)) {
            throw New-Object System.Exception("Unable to initialize environment for data collection")
        }

        # dump out the regkey properties
        Export-RegistryKeyConfigDetails -Path $config.properties.regKeyPaths -OutputDirectory $regDir.FullName

        # enumerate dll binary version for NC application
        $ncAppDirectories = Get-ChildItem -Path "C:\Windows\NetworkController" -Directory
        foreach ($directory in $ncAppDirectories) {
            [System.String]$fileName = "FileInfo_{0}" -f $directory.BaseName
            Get-Item -Path "$($directory.FullName)\*" -Include *.dll, *.exe | Export-ObjectToFile -FilePath $ncAppDir.FullName -Name $fileName -FileType txt -Format List
        }

        Get-SdnGeneralConfigurationState -OutputDirectory $OutputDirectory.FullName
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }

    $ProgressPreference = 'Continue'
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

    try {

        if (-NOT ($PSBoundParameters.ContainsKey('NetworkController'))) {
            $config = Get-SdnRoleConfiguration -Role 'NetworkController'
            $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
            if (-NOT ($confirmFeatures)) {
                "The current machine is not a NetworkController, run this on NetworkController or use -NetworkController parameter to specify one" | Trace-Output -Level:Warning
                return # don't throw exception, since this is a controlled scenario and we do not need stack exception tracing
            }
        }

        try {
            if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
                $result = Get-NetworkControllerNode -ErrorAction Stop
            }
            else {
                $result = Invoke-PSRemoteCommand -ComputerName $NetworkController -Credential $Credential -ScriptBlock {
                    Get-NetworkControllerNode -ErrorAction Stop
                } -ErrorAction Stop
            }

            # in this scenario if the results returned we will parse the objects returned and generate warning to user if node is not up
            # this property is only going to exist though if service fabric is healthy and underlying NC cmdlet can query node status
            foreach ($obj in $result) {
                if ($obj.Status -ine 'Up') {
                    "{0} is reporting status {1}" -f $obj.Name, $obj.Status | Trace-Output -Level:Warning
                }

                # if we returned the object, we want to add a new property called NodeCertificateThumbprint as this will ensure consistent
                # output in scenarios where this operation fails due to NC unhealthy and we need to fallback to reading the cluster manifest
                $result | ForEach-Object {
                    if (!($_.PSOBject.Properties.name -contains "NodeCertificateThumbprint")) {
                        $_ | Add-Member -MemberType NoteProperty -Name 'NodeCertificateThumbprint' -Value $_.NodeCertificate.Thumbprint
                    }
                }
            }
        }
        catch {
            "Get-NetworkControllerNode failed with following exception: `n`t{0}`n" -f $_ | Trace-Output -Level:Exception
            $result = Get-NetworkControllerNodeInfoFromClusterManifest  -NetworkController $NetworkController -Credential $Credential
        }

        if ($Name) {
            $result = $result | Where-Object { $_.Name.Split(".")[0] -ieq $Name.Split(".")[0] -or $_.Server -ieq $Name.Split(".")[0] }
        }

        if ($ServerNameOnly) {
            return [System.Array]$result.Server
        }
        else {
            return $result
        }

    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnNetworkControllerNodeCertificate {
    <#
    .SYNOPSIS
        Returns the current Network Controller node certificate
    #>

    try {
        $networkControllerNode = Get-SdnNetworkControllerNode -Name $env:COMPUTERNAME

        # check to see if FindCertificateBy property exists as this was added in later builds
        # else if does not exist, default to Thumbprint for certificate
        if ($null -ne $networkControllerNode.FindCertificateBy) {
            "Network Controller is currently configured for FindCertificateBy: {0}" -f $networkControllerNode.FindCertificateBy | Trace-Output -Level:Verbose
            switch ($networkControllerNode.FindCertificateBy) {
                'FindBySubjectName' {
                    "`tFindBySubjectName: {0}" -f $networkControllerNode.NodeCertSubjectName | Trace-Output -Level:Verbose
                    $certificate = Get-SdnCertificate -Path 'Cert:\LocalMachine\My' -Subject $networkControllerNode.NodeCertSubjectName
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
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnNetworkControllerRestCertificate {
    <#
    .SYNOPSIS
        Returns the current Network Controller REST Certificate
    #>

    try {

        $config = Get-SdnRoleConfiguration -Role 'NetworkController'
        $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
        if (-NOT ($confirmFeatures)) {
            "The current machine is not a NetworkController, run this on NetworkController or use -NetworkController parameter to specify one" | Trace-Output -Level:Warning
            return # don't throw exception, since this is a controlled scenario and we do not need stack exception tracing
        }

        try {
            $networkController = Get-SdnNetworkController
            $ncRestCertThumprint = $($networkController.ServerCertificate.Thumbprint).ToString()
        }
        catch {
            "Unable to retrieve NetworkController Certificate Info directly from Get-NetworkController. Attempting to retrieve info from ClusterManifest" | Trace-Output -Level:Warning
            $ncInfo = Get-SdnNetworkControllerInfoOffline
            $ncRestCertThumprint = $ncInfo.NcRestCertThumbprint
        }

        $certificate = Get-SdnCertificate -Path 'Cert:\LocalMachine\My' -Thumbprint $ncRestCertThumprint

        if ($null -eq $certificate) {
            throw New-Object System.NullReferenceException("Unable to locate Network Controller Rest Certificate")
        }

        return $certificate
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
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
		Specifies a user account that has permission to perform this action. The default is the current user.
	.PARAMETER NcRestCredential
		Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    .PARAMETER ExecutionTimeout
        Specify the execution timeout (seconds) on how long you want to wait for operation to complete before cancelling operation. If omitted, defaults to 300 seconds.
    .EXAMPLE
        PS> Get-SdnNcImosDumpFiles -NcUri "https://nc.contoso.com" -NetworkController $NetworkControllers -OutputDirectory "C:\Temp\CSS_SDN"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$NetworkController,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [int]$ExecutionTimeOut = 300
    )
    try {
        $config = Get-SdnRoleConfiguration -Role:NetworkController
        [System.IO.FileInfo]$netControllerStatePath = $config.properties.netControllerStatePath
        [System.IO.FileInfo]$outputDir = Join-Path -Path $OutputDirectory.FullName -ChildPath 'NetworkControllerState'

        if (!(Test-Path -Path $outputDir.FullName -PathType Container)) {
            $null = New-Item -Path $outputDir.FullName -ItemType Directory -Force
        }

        $scriptBlock = {
            try {
                if (Test-Path -Path $using:netControllerStatePath.FullName -PathType Container) {
                    Get-Item -Path $using:netControllerStatePath.FullName | Remove-Item -Recurse -Confirm:$false -Force -ErrorAction SilentlyContinue
                }

                $null = New-Item -Path $using:netControllerStatePath.FullName -ItemType Container -Force
            }
            catch {
                $_ | Write-Error
            }
        }

        $infraInfo = Get-SdnInfrastructureInfo -NetworkController $NetworkController -Credential $Credential -NcRestCredential $NcRestCredential
        # invoke scriptblock to clean up any stale NetworkControllerState files
        Invoke-PSRemoteCommand -ComputerName $infraInfo.NetworkController -ScriptBlock $scriptBlock -Credential $Credential

        # invoke the call to generate the files
        # once the operation completes and returns true, then enumerate through the Network Controllers defined to collect the files
        $result = Invoke-SdnNetworkControllerStateDump -NcUri $infraInfo.NcUrl -Credential $NcRestCredential -ExecutionTimeOut $ExecutionTimeOut
        if ($result) {
            foreach ($ncVM in $infraInfo.NetworkController) {
                Copy-FileFromRemoteComputer -Path "$($config.properties.netControllerStatePath)\*" -ComputerName $ncVM -Destination $outputDir.FullName
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
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
    .PARAMETER ResourceName
    .PARAMETER InstanceID
    .PARAMETER ApiVersion
        The API version to use when invoking against the NC REST API endpoint.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnResource -Resource PublicIPAddresses
    .EXAMPLE
        PS> Get-SdnResource -NcUri "https://nc.$env:USERDNSDOMAIN" -ResourceRef "/publicIPAddresses/d9266251-a3ba-4ac5-859e-2c3a7c70352a"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Resource')]
        [Parameter(Mandatory = $true, ParameterSetName = 'InstanceID')]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [System.String]$ResourceRef,

        [Parameter(Mandatory = $true, ParameterSetName = 'Resource')]
        [SdnApiResource]$Resource,

        [Parameter(Mandatory = $false, ParameterSetName = 'Resource')]
        [System.String]$ResourceId,

        [Parameter(Mandatory = $true, ParameterSetName = 'InstanceID')]
        [System.String]$InstanceId,

        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Resource')]
        [System.String]$ApiVersion = $Global:SdnDiagnostics.InfrastructureInfo.RestApiVersion,

        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Resource')]
        [Parameter(Mandatory = $false, ParameterSetName = 'InstanceID')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        switch ($PSCmdlet.ParameterSetName) {
            'InstanceId' {
                [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri.AbsoluteUri -ApiVersion $ApiVersion -ResourceName 'internalResourceInstances'
                [System.String]$uri = "{0}/{1}" -f $uri, $InstanceId.Trim()
            }
            'ResourceRef' {
                [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri.AbsoluteUri -ApiVersion $ApiVersion -ResourceRef $ResourceRef
            }
            'Resource' {
                [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri.AbsoluteUri -ApiVersion $ApiVersion -ResourceName $Resource

                if ($ResourceID) {
                    [System.String]$uri = "{0}/{1}" -f $uri, $ResourceId.Trim()
                }
            }
        }

        "{0} {1}" -f $method, $uri | Trace-Output -Level:Verbose

        # gracefully handle System.Net.WebException responses such as 404 to throw warning
        # anything else we want to throw terminating exception and capture for debugging purposes
        try {
            $result = Invoke-RestMethodWithRetry -Uri $uri -Method 'GET' -UseBasicParsing -Credential $Credential -ErrorAction Stop
        }
        catch [System.Net.WebException] {
            "{0} ({1})" -f $_.Exception.Message, $_.Exception.Response.ResponseUri.AbsoluteUri | Write-Warning
            return $null
        }
        catch {
            throw $_
        }

        # if multiple objects are returned, they will be nested under a property called value
        # so we want to do some manual work here to ensure we have a consistent behavior on data returned back
        if ($result.value) {
            return $result.value
        }

        # in some instances if the API returns empty object, we will see it saved as 'nextLink' which is a empty string property
        # we need to return null instead otherwise the empty string will cause calling functions to treat the value as it contains data
        elseif ($result.PSObject.Properties.Name -ieq "nextLink" -and $result.PSObject.Properties.Name.Count -eq 1) {
            return $null
        }

        return $result
    }
    catch {
        "{0}`nAbsoluteUri:{1}`n{2}" -f $_.Exception, $_.TargetObject.Address.AbsoluteUri, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnServer {
    <#
    .SYNOPSIS
        Returns a list of servers from network controller.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER ManagementAddressOnly
        Optional parameter to only return back the Management Address value.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [switch]$ManagementAddressOnly
    )

    try {
        $result = Get-SdnResource -NcUri $NcUri.AbsoluteUri -Resource:Servers -Credential $Credential
        if ($result) {
            foreach ($obj in $result) {
                if ($obj.properties.provisioningState -ne 'Succeeded') {
                    "{0} is reporting provisioningState: {1}" -f $obj.resourceId, $obj.properties.provisioningState | Trace-Output -Level:Warning
                }
            }

            if ($ManagementAddressOnly) {
                # there might be multiple connection endpoints to each node so we will want to only return the unique results
                # this does not handle if some duplicate connections are listed as IPAddress with another record saved as NetBIOS or FQDN
                # further processing may be required by the calling function to handle that
                return ($result.properties.connections.managementAddresses | Sort-Object -Unique)
            }
            else {
                return $result
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Invoke-SdnResourceDump {
    <#
    .SYNOPSIS
        Returns a list of gateways from network controller
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
	.PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Invoke-SdnResourceDump
    .EXAMPLE
        PS> Invoke-SdnResourceDump -NcUri "https://nc.contoso.com"
    .EXAMPLE
        PS> Invoke-SdnResourceDump -NcUri "https://nc.contoso.com" -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        [System.IO.FileInfo]$outputDir = Join-Path -Path $OutputDirectory.FullName -ChildPath 'SdnApiResources'
        if (!(Test-Path -Path $outputDir.FullName -PathType Container)) {
            $null = New-Item -Path $outputDir.FullName -ItemType Directory -Force
        }

        $apiVersion = (Get-SdnDiscovery -NcUri $NcUri.AbsoluteUri -Credential $Credential).currentRestVersion
        if ($null -ieq $apiVersion) {
            $apiVersion = 'v1'
        }

        $config = Get-SdnRoleConfiguration -Role:NetworkController
        [int]$apiVersionInt = $ApiVersion.Replace('v', '').Replace('V', '')
        foreach ($resource in $config.properties.apiResources.Values) {

            # skip any resources that are not designed to be exported
            if ($resource.includeInResourceDump -ieq $false) {
                continue
            }

            [int]$minVersionInt = $resource.minVersion.Replace('v', '').Replace('V', '')
            if ($minVersionInt -le $apiVersionInt) {
                $sdnResource = Get-SdnResource -NcUri $NcUri.AbsoluteUri -ResourceRef $resource.uri -Credential $Credential
                if ($sdnResource) {
                    $sdnResource | Export-ObjectToFile -FilePath $outputDir.FullName -Name $resource.name -FileType json
                }
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

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
            $config = Get-SdnRoleConfiguration -Role 'NetworkController'
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
                $keyLookup = @('Gateway', 'NetworkController', 'Server', 'LoadBalancerMux')
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

                    Invoke-SdnResourceDump -NcUri $sdnFabricDetails.NcUrl -OutputDirectory $OutputDirectory.FullName -Credential $NcRestCredential
                    Get-SdnNetworkControllerState -NetworkController $NetworkController -OutputDirectory $OutputDirectory.FullName `
                        -Credential $Credential -NcRestCredential $NcRestCredential
                    Get-SdnNetworkControllerClusterInfo -NetworkController $NetworkController -OutputDirectory $OutputDirectory.FullName `
                        -Credential $Credential
                }

                'Server' {
                    Invoke-PSRemoteCommand -ComputerName $dataNodes -ScriptBlock {
                        Get-SdnServerConfigurationState -OutputDirectory $using:tempDirectory.FullName
                    } -Credential $Credential -AsJob -PassThru -Activity 'Get-SdnServerConfigurationState'

                    Get-SdnProviderAddress -ComputerName $dataNodes -Credential $Credential `
                    | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnProviderAddress' -FileType csv

                    Get-SdnVfpVmSwitchPort -ComputerName $dataNodes -Credential $Credential `
                    | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnVfpVmSwitchPort' -FileType csv

                    Get-SdnVMNetworkAdapter -ComputerName $dataNodes -Credential $Credential -AsJob -PassThru -Timeout 900 `
                    | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnVMNetworkAdapter' -FileType csv
                }

                'LoadBalancerMux' {
                    Invoke-PSRemoteCommand -ComputerName $dataNodes -ScriptBlock {
                        Get-SdnSlbMuxConfigurationState -OutputDirectory $using:tempDirectory.FullName
                    } -Credential $Credential -AsJob -PassThru -Activity 'Get-SdnSlbMuxConfigurationState'

                    $slbStateInfo = Get-SdnSlbStateInformation -NcUri $sdnFabricDetails.NcUrl -Credential $NcRestCredential
                    $slbStateInfo | ConvertTo-Json -Depth 100 | Out-File "$($OutputDirectory.FullName)\SlbState.Json"
                }
            }

            # check to see if any network traces were captured on the data nodes previously
            "Checking for any previous network traces and moving them into {0}" -f $tempDirectory.FullName | Trace-Output
            Invoke-PSRemoteCommand -ComputerName $dataNodes -ScriptBlock {
                [System.IO.FileInfo]$networkTraceDir = "$($using:workingDirectory)\NetworkTraces"
                if (Test-Path -Path $networkTraceDir.FullName -PathType Container) {

                    # convert the most recent etl trace file into human readable format without requirement of additional parsing tools
                    if ($using:ConvertETW) {
                        $convertFile = Get-Item -Path "$($networkTraceDir.FullName)\*" -Include '*.etl' | Sort-Object -Property LastWriteTime | Select-Object -Last 1
                        if ($convertFile) {
                            $null = Convert-SdnEtwTraceToTxt -FileName $convertFile.FullName -Overwrite 'Yes'
                        }
                    }

                    # move the entire directory
                    try {
                        Move-Item -Path "$($using:workingDirectory.FullName)\NetworkTraces" -Destination $using:tempDirectory.FullName -Force -ErrorAction Stop
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

                if ($group.Name -ieq 'Server') {
                    Get-SdnAuditLog -NcUri $NcUri.AbsoluteUri -NcRestCredential $NcRestCredential -OutputDirectory "$($OutputDirectory.FullName)\AuditLogs" `
                        -ComputerName $dataNodes -Credential $Credential
                }

                "Collect diagnostics logs for {0} nodes: {1}" -f $group.Name, ($dataNodes -join ', ') | Trace-Output
                Invoke-PSRemoteCommand -ComputerName $dataNodes -ScriptBlock {
                    Get-SdnDiagnosticLog -OutputDirectory $using:tempDirectory.FullName -FromDate $using:FromDate -ConvertETW $using:ConvertETW
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

function Get-SdnAuditLog {
    <#
    .SYNOPSIS
        Collects the audit logs for Network Security Groups (NSG) from the hypervisor hosts
    .PARAMETER OutputDirectory
        Directory the results will be saved to. If ommitted, will default to the current working directory.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER NCRestCredential
        Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote compute
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$OutputDirectory = "$(Get-WorkingDirectory)\AuditLogs",

        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    begin {
        # verify that the environment we are on supports at least v3 API and later
        # as described in https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ncnbi/dc23b547-9ec4-4cb3-ab20-a6bfe01ddafb
        $currentRestVersion = (Get-SdnResource -NcUri $NcUri.AbsoluteUri -Resource 'Discovery' -Credential $NcRestCredential).properties.currentRestVersion
        [int]$currentRestVersionInt = $currentRestVersion.Replace('V', '').Replace('v', '').Trim()
        if ($currentRestVersionInt -lt 3) {
            "Auditing requires API version 3 or later. Network Controller supports version {0}" -f $currentRestVersionInt | Trace-Output -Level:Warning
            return
        }

        # check to see that auditing has been enabled
        $auditSettingsConfig = Get-SdnResource -NcUri $NcUri.AbsoluteUri -Resource 'AuditingSettingsConfig' -ApiVersion $currentRestVersion -Credential $NcRestCredential
        if ([string]::IsNullOrEmpty($auditSettingsConfig.properties.outputDirectory)) {
            "Audit logging is not enabled" | Trace-Output
            return
        }
        else {
            "Audit logging location: {0}" -f $auditSettingsConfig.properties.outputDirectory | Trace-Output
        }

        # if $ComputerName was not specified, then attempt to locate the servers within the SDN fabric
        # only add the servers where auditingEnabled has been configured as 'Firewall'
        if ($null -eq $ComputerName) {
            $sdnServers = Get-SdnResource -Resource Servers -NcUri $NcUri.AbsoluteUri -Credential $NcRestCredential -ApiVersion $currentRestVersion `
            | Where-Object { $_.properties.auditingEnabled -ieq 'Firewall' }

            $ComputerName = ($sdnServers.properties.connections | Where-Object { $_.credentialType -ieq 'UsernamePassword' }).managementAddresses
        }
    }

    process {
        $ComputerName | ForEach-Object {
            "Collecting audit logs from {0}" -f $_ | Trace-Output
            $outputDir = Join-Path -Path $OutputDirectory -ChildPath $_.ToLower()
            Copy-FileFromRemoteComputer -ComputerName $_ -Credential $Credential -Path $auditSettingsConfig.properties.outputDirectory -Destination $outputDir -Recurse -Force
        }
    }
}
