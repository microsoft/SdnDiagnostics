#
# Module manifest for diagnostics for Software Defined Networking.
#
# Copyright='© Microsoft Corporation. All rights reserved.'
#

@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'SDNDiagnostics.psm1'

    # Author of this module
    Author = 'Microsoft Corporation'

    # Company or vendor of this module
    CompanyName = 'Microsoft Corporation'

    # Copyright statement for this module
    Copyright = '© Microsoft Corporation. All rights reserved.'

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
        'Get-SdnServiceFabricNode'
        'Get-SdnServiceFabricReplica',
        'Get-SdnServiceFabricService',
        'Get-SdnSlbMuxConfigurationState'
        'Get-SdnSlbStateInformation',
        'Get-SdnVfpVmSwitchPort',
        'Get-VfpVmSwitchPort',
        'Get-VMNetAdapter',
        'Get-VMNetAdapterPortProfile',
        'Install-SdnDiagnostic',
        'Invoke-SdnServiceFabricCommand',
        'Move-SdnServiceFabricReplica',
        'Start-SdnDataCollection'
    )

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @()
}
