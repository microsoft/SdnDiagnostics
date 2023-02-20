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

enum TraceLevel {
    Error
    Exception
    Information
    Success
    Verbose
    Warning
}

enum OvsdbTable {
    ms_vtep
    ms_firewall
    ServiceInsertion
}

enum VMState {
    Other
    Running
    Off
    Stopping
    Saved
    Paused
    Starting
    Reset
    Saving
    Pausing
    Resuming
    FastSaved
    FastSaving
    RunningCritical
    OffCritical
    StoppingCritical
    SavedCritical
    PausedCritical
    StartingCritical
    ResetCritical
    SavingCritical
    PausingCritical
    ResumingCritical
    FastSavedCritical
    FastSavingCritical
}
