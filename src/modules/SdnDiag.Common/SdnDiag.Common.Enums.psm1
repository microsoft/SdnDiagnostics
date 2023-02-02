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

enum TraceLevel {
    Error
    Exception
    Information
    Success
    Verbose
    Warning
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

enum OvsdbTable {
    ms_vtep
    ms_firewall
    ServiceInsertion
}

enum NcManagedRoles {
    Gateway
    Server
    LoadBalancerMux
}

enum NcAppServices {
    ApiService
    BackupRestore
    ControllerService
    FirewallService
    FnmService
    GatewayManager
    HelperService
    ServiceInsertion
    SlbManagerService
    UpdateService
    VSwitchService
}
