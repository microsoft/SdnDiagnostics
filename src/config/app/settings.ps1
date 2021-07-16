New-Variable -Name SdnDiagnostics -Scope Global -Force -Value @{
    Cache = @{}
    NcUrl = $null
    Settings = (Get-Content -Path "$PSScriptRoot\settings.json" | ConvertFrom-Json)
    TraceFilePath = $null
    WorkingDirectory = $null
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