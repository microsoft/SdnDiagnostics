# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

class SdnFabricInfrastructure {
    [System.String[]]$NetworkController
    [System.String[]]$LoadBalancerMux
    [System.String[]]$Gateway
    [System.String]$NcUrl
    [System.String]$RestApiVersion
    [System.String[]]$FabricNodes
}

enum NcManagedRoles {
    Gateway
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

$scriptBlocks = @{
    ServiceFabricServiceName = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $serviceName = @(
            'fabric:/NetworkController/ApiService'
            'fabric:/NetworkController/BackupRestore'
            'fabric:/NetworkController/ControllerService'
            'fabric:/NetworkController/FirewallService'
            'fabric:/NetworkController/FnmService'
            'fabric:/NetworkController/GatewayManager'
            'fabric:/NetworkController/HelperService'
            'fabric:/NetworkController/ServiceInsertion'
            'fabric:/NetworkController/SlbManagerService'
            'fabric:/NetworkController/UpdateService'
            'fabric:/NetworkController/VSwitchService'
        )

        if ([string]::IsNullOrEmpty($wordToComplete)) {
            return ($serviceName | Sort-Object)
        }
    }

    ServiceFabricServiceTypeName = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $serviceTypeName = @(
            'ApiService'
            'BackupRestore'
            'ControllerService'
            'FirewallService'
            'FnmService'
            'GatewayManager'
            'HelperService'
            'ServiceInsertion'
            'SlbManagerService'
            'UpdateService'
            'VSwitchService'
        )

        if ([string]::IsNullOrEmpty($wordToComplete)) {
            return ($serviceTypeName | Sort-Object)
        }
    }
}

Register-ArgumentCompleter -CommandName 'Get-SdnServiceFabricReplica' -ParameterName 'ServiceName' -ScriptBlock $scriptBlocks.ServiceFabricServiceName
Register-ArgumentCompleter -CommandName 'Get-SdnServiceFabricReplica' -ParameterName 'ServiceTypeName' -ScriptBlock $scriptBlocks.ServiceFabricServiceTypeName

Register-ArgumentCompleter -CommandName 'Get-SdnServiceFabricService' -ParameterName 'ServiceName' -ScriptBlock $scriptBlocks.ServiceFabricServiceName
Register-ArgumentCompleter -CommandName 'Get-SdnServiceFabricService' -ParameterName 'ServiceTypeName' -ScriptBlock $scriptBlocks.ServiceFabricServiceTypeName

Register-ArgumentCompleter -CommandName 'Get-SdnServiceFabricPartition' -ParameterName 'ServiceName' -ScriptBlock $scriptBlocks.ServiceFabricServiceName
Register-ArgumentCompleter -CommandName 'Get-SdnServiceFabricPartition' -ParameterName 'ServiceTypeName' -ScriptBlock $scriptBlocks.ServiceFabricServiceTypeName

Register-ArgumentCompleter -CommandName 'Move-SdnServiceFabricReplica' -ParameterName 'ServiceName' -ScriptBlock $scriptBlocks.ServiceFabricServiceName
Register-ArgumentCompleter -CommandName 'Move-SdnServiceFabricReplica' -ParameterName 'ServiceTypeName' -ScriptBlock $scriptBlocks.ServiceFabricServiceTypeName
