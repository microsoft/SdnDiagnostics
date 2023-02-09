# Module manifest for diagnostics for Software Defined Networking.
#
# Copyright='© Microsoft Corporation. All rights reserved.'
# Licensed under the MIT License.

@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'SdnDiagnostics.psm1'

    # Author of this module
    Author = 'Adam Rudell'

    # Company or vendor of this module
    CompanyName = 'Microsoft Corporation'

    # Copyright statement for this module
    Copyright = '(c) Microsoft Corporation. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'SdnDiagnostics is a tool used to simplify the data collection and diagnostics of Windows Software Defined Networking.'

    # Version number of this module.
    ModuleVersion = '1.0.0.0'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules = @(
        'modules\ArgumentCompleters.psm1'
        'modules\SdnDiag.Common\SdnDiag.Common'
        'modules\SdnDiag.Fabric.Health\SdnDiag.Fabric.Health'
        'modules\SdnDiag.Gateway\SdnDiag.Gateway'
        'modules\SdnDiag.LoadBalancer\SdnDiag.LoadBalancer'
        'modules\SdnDiag.NetworkController\SdnDiag.NetworkController'
        'modules\SdnDiag.Server\SdnDiag.Server'
    )

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @()

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Functions to export from this module
    FunctionsToExport = @(
        'Clear-SdnWorkingDirectory',
        'Convert-SdnEtwTraceToTxt',
        'Debug-SdnFabricInfrastructure',
        'Disable-SdnRasGatewayTracing',
        'Enable-SdnRasGatewayTracing',
        'Get-SdnApiEndpoint'
        'Get-SdnCertificate',
        'Get-SdnDiagnosticLog',
        'Get-SdnEventLog',
        'Get-SdnFabricInfrastructureHealth',
        'Get-SdnGateway',
        'Get-SdnGatewayConfigurationState',
        'Get-SdnInfrastructureInfo',
        'Get-SdnKnownIssue',
        'Get-SdnMuxDistributedRouterIP',
        'Get-SdnMuxState',
        'Get-SdnMuxStatefulVip',
        'Get-SdnMuxStatelessVip',
        'Get-SdnMuxStats',
        'Get-SdnMuxVip',
        'Get-SdnMuxVipConfig',
        'Get-SdnLoadBalancerMux',
        'Get-SdnNetAdapterEncapOverheadConfig',
        'Get-SdnNetAdapterRdmaConfig',
        'Get-SdnNetworkInterfaceOutboundPublicIPAddress',
        'Get-SdnNetworkController',
        'Get-SdnNetworkControllerClusterInfo',
        'Get-SdnNetworkControllerConfigurationState',
        'Get-SdnNetworkControllerClusterInfo',
        'Get-SdnNetworkControllerNode',
        'Get-SdnNetworkControllerNodeCertificate'
        'Get-SdnNetworkControllerRestCertificate',
        'Get-SdnNetworkControllerState',
        'Get-SdnOvsdbAddressMapping',
        'Get-SdnOvsdbFirewallRuleTable',
        'Get-SdnOvsdbGlobalTable',
        'Get-SdnOvsdbPhysicalPortTable',
        'Get-SdnOvsdbUcastMacRemoteTable',
        'Get-SdnProviderAddress',
        'Get-SdnResource',
        'Get-SdnServer',
        'Get-SdnServerConfigurationState',
        'Get-SdnServiceFabricApplicationHealth',
        'Get-SdnServiceFabricClusterConfig',
        'Get-SdnServiceFabricClusterHealth',
        'Get-SdnServiceFabricClusterManifest',
        'Get-SdnServiceFabricLog',
        'Get-SdnServiceFabricNode',
        'Get-SdnServiceFabricPartition',
        'Get-SdnServiceFabricReplica',
        'Get-SdnServiceFabricService',
        'Get-SdnSlbMuxConfigurationState',
        'Get-SdnSlbStateInformation',
        'Get-SdnVfpVmSwitchPort',
        'Get-SdnVMNetworkAdapter',
        'Get-SdnVMNetworkAdapterPortProfile',
        'Get-SdnVfpPortGroup',
        'Get-SdnVfpPortLayer',
        'Get-SdnVfpPortRule',
        'Get-SdnVfpPortState',
        'Import-SdnCertificate',
        'Install-SdnDiagnostics',
        'Invoke-SdnCommand',
        'Invoke-SdnGetNetView',
        'Invoke-SdnResourceDump',
        'Invoke-SdnServiceFabricCommand',
        'Move-SdnServiceFabricReplica',
        'New-SdnCertificate',
        'New-SdnCertificateRotationConfig',
        'New-SdnNetworkControllerNodeCertificate',
        'New-SdnNetworkControllerRestCertificate',
        'Set-SdnCertificateAcl',
        'Set-SdnServiceFabricClusterConfig',
        'Set-SdnVMNetworkAdapterPortProfile',
        'Show-SdnVfpPortConfig',
        'Start-SdnCertificateRotation',
        'Start-SdnDataCollection',
        'Start-SdnEtwTraceCapture',
        'Start-SdnNetshTrace',
        'Stop-SdnEtwTraceCapture',
        'Stop-SdnNetshTrace',
        'Test-SdnCertificateRotationConfig',
        'Test-SdnKIHostRootStoreNonRootCert',
        'Test-SdnKINetworkControllerCertCredential',
        'Test-SdnKINetworkInterfaceAPIDuplicateMacAddress',
        'Test-SdnKINetworkInterfacePlacement',
        'Test-SdnKIServerHostId',
        'Test-SdnKIServiceFabricPartitionDatabaseSize',
        'Test-SdnKIVfpDuplicatePort',
        'Test-SdnKIVMNetAdapterDuplicateMacAddress',
        'Test-SdnEncapOverhead',
        'Test-SdnGatewayConfigState',
        'Test-SdnGatewayServiceState',
        'Test-SdnKnownIssue',
        'Test-SdnLoadBalancerMuxConfigState',
        'Test-SdnLoadBalancerMuxServiceState',
        'Test-SdnNetworkControllerServiceState',
        'Test-SdnProviderAddressConnectivity',
        'Test-SdnProviderNetwork',
        'Test-SdnServerConfigState',
        'Test-SdnServerServiceState'
    )

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @(
                'MSFTNet', 'Networking','Sdn'
            )

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/microsoft/SdnDiagnostics'

            # A URL to the license for this module.
            LicenseUri = 'https://microsoft.mit-license.org/'

            # External dependent modules of this module
            ExternalModuleDependencies = @()
        }
    }
}
