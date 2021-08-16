#
# Module manifest for diagnostics for Software Defined Networking.
#
# Copyright='© Microsoft Corporation. All rights reserved.'
#

@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'SdnDiagnostics.psm1'

    # Author of this module
    Author = 'Adam Rudell'

    # Company or vendor of this module
    CompanyName = 'Microsoft Corporation'

    # Copyright statement for this module
    Copyright = '© Microsoft Corporation. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'SdnDiagnostics is a tool used to simplify the data collection and diagnostics of Windows Software Defined Networking.'

    # Version number of this module.
    ModuleVersion = '1.0.0.0'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules = @()

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @(
        'CimCmdlets',
        'DnsClient',
        'Microsoft.PowerShell.Archive',
        'NetSecurity',
        'NetTCPIP',
        'SmbShare'
    )

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Functions to export from this module
    FunctionsToExport = @(
        'Debug-SdnFabricInfrastructure',
        'Get-OvsdbAddressMapping',
        'Get-OvsdbFirewallRuleTable',
        'Get-OvsdbGlobalTable',
        'Get-OvsdbPhysicalPortTable',
        'Get-OvsdbUcastMacRemoteTable',
        'Get-SdnApiResource',
        'Get-SdnDiagnosticLog',
        'Get-SdnEventLog'
        'Get-SdnGatewayConfigurationState',
        'Get-SdnGateway',
        'Get-SdnInfrastructureInfo',
        'Get-SdnLoadBalancerMux',
        'Get-SdnNetControllerConfigurationState',
        'Get-SdnNetworkController',
        'Get-SdnNetworkControllerState',
        'Get-SdnOvsdbAddressMapping',
        'Get-SdnOvsdbFirewallRuleTable',
        'Get-SdnOvsdbGlobalTable',
        'Get-SdnOvsdbPhysicalPortTable',
        'Get-SdnOvsdbUcastMacRemoteTable',
        'Get-SdnProviderAddress',
        'Get-SdnResource',
        'Get-SdnServerConfigurationState',
        'Get-SdnServer',
        'Get-SdnServiceFabricApplicationHealth',
        'Get-SdnServiceFabricClusterHealth',
        'Get-SdnServiceFabricClusterManifest',
        'Get-SdnServiceFabricLog',
        'Get-SdnServiceFabricNode'
        'Get-SdnServiceFabricReplica',
        'Get-SdnServiceFabricService',
        'Get-SdnSlbMuxConfigurationState'
        'Get-SdnSlbStateInformation',
        'Get-SdnVfpVmSwitchPort',
        'Get-VfpVmSwitchPort',
        'Get-SdnVMNetAdapter',
        'Get-VMNetAdapterPortProfile',
        'Install-SdnDiagnostic',
        'Invoke-SdnGetNetView',
        'Invoke-SdnServiceFabricCommand',
        'Move-SdnServiceFabricReplica',
        'Start-SdnDataCollection',
        'Start-SdnTraceCapture',
        'Stop-SdnTraceCapture',
        'Test-SdnKnownIssue'
    )

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @()
}
