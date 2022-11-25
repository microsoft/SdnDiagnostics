# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnApiEndpoint {
    <##>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $true, ParameterSetName = 'NoResourceRef')]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $false, ParameterSetName = 'NoResourceRef')]
        [System.String]$ApiVersion = $Global:SdnDiagnostics.EnvironmentInfo.RestApiVersion,

        [Parameter(Mandatory = $true, ParameterSetName = 'NoResourceRef')]
        [System.String]$ServiceName,

        [Parameter(Mandatory = $false, ParameterSetName = 'NoResourceRef')]
        [System.String]$OperationId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceRef')]
        [System.String]$ResourceRef
    )

    try {
        $apiEndpoints = @{
            AccessControlLists = "networking/{0}/accessControlLists" -f $ApiVersion
            AuditingSettingsConfig = "networking/{0}/auditingSettings/configuration" -f $ApiVersion
            Credentials = "networking/{0}/credentials" -f $ApiVersion
            Discovery = "networking/discovery"
            GatewayPools = "networking/{0}/gatewayPools" -f $ApiVersion
            Gateways = "networking/{0}/gateways" -f $ApiVersion
            iDNSServerConfig = "networking/{0}/iDNSServer/configuration" -f $ApiVersion
            LearnedIPAddresses ="/networking/{0}/learnedIpAddresses" -f $ApiVersion
            LoadBalancerManagerConfig = "networking/{0}/loadBalancerManager/config" -f $ApiVersion
            LoadBalancerMuxes = "networking/{0}/loadBalancerMuxes" -f $ApiVersion
            LoadBalancers = "networking/{0}/loadBalancers" -f $ApiVersion
            LogicalNetworks = "networking/{0}/logicalNetworks" -f $ApiVersion
            MacPools = "networking/{0}/macPools" -f $ApiVersion
            NetworkControllerState = "networking/{0}/diagnostics/networkControllerState" -f $ApiVersion
            NetworkControllerStatistics = "networking/{0}/monitoring/networkControllerStatistics" -f $ApiVersion
            NetworkInterfaces = "networking/{0}/networkInterfaces" -f $ApiVersion
            PublicIPAddresses = "networking/{0}/publicIPAddresses" -f $ApiVersion
            SecurityTags = "networking/{0}/securityTags" -f $ApiVersion
            ServiceInsertions = "networking/{0}/serviceInsertions" -f $ApiVersion
            Servers = "networking/{0}/servers" -f $ApiVersion
            SlbState = "networking/{0}/diagnostics/slbState" -f $ApiVersion
            SlbStateResults = "networking/{0}/diagnostics/slbStateResults/{1}" -f $ApiVersion, $OperationId
            RouteTables = "networking/{0}/routeTables" -f $ApiVersion
            VirtualGateways = "networking/{0}/virtualGateways" -f $ApiVersion
            VirtualNetworkManagerConfig = "networking/{0}/virtualNetworkManager/configuration" -f $ApiVersion
            VirtualNetworks = "networking/{0}/virtualNetworks" -f $ApiVersion
            VirtualServers = "networking/{0}/virtualServers" -f $ApiVersion
            VirtualSwitchManagerConfig = "networking/{0}/virtualSwitchManager/configuration" -f $ApiVersion
        }

        if($PSBoundParameters.ContainsKey('ResourceRef')){
            [System.String]$endpoint = "{0}/networking/{1}/{2}" -f $NcUri.AbsoluteUri.TrimEnd('/'), $ApiVersion, $ResourceRef.TrimStart('/')
        }
        else {
            [System.String]$endpoint = "{0}/{1}" -f $NcUri.AbsoluteUri.TrimEnd('/'), $apiEndpoints[$ServiceName]
        }

        "Endpoint: {0}" -f $endpoint | Trace-Output -Level:Verbose
        return $endpoint
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
