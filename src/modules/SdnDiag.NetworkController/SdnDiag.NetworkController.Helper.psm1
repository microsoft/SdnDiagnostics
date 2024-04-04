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
