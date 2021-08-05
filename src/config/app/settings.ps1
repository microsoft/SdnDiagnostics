New-Variable -Name SdnDiagnostics -Scope Global -Force -Value @{
    Cache = @{}
    Credential = $null
    EnvironmentInfo = @{}
    Settings = (Get-Content -Path "$PSScriptRoot\settings.json" | ConvertFrom-Json)
    TraceFilePath = $null
}

enum TraceLevel {
    Error
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

enum SdnRoles {
    NetworkController
    Gateway
    Server
    SoftwareLoadBalancer
}

enum NcManagedRoles {
    Gateway
    Server
    SoftwareLoadBalancer
}

enum SdnApiResource {
    AccessControlLists
    Credentials
    GatewayPools
    Gateways
    iDNSServerConfig
    LoadBalancerManagerConfig
    LoadBalancerMuxes
    LoadBalancers
    LogicalNetworks
    MacPools
    NetworkControllerState
    NetworkInterfaces
    PublicIPAddresses
    Servers
    SlbState
    RouteTables
    VirtualGateways
    VirtualNetworkManagerConfig
    VirtualNetworks
    VirtualServers
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