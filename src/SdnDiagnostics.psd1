# Module manifest for diagnostics for Software Defined Networking.
#
# Copyright='© Microsoft Corporation. All rights reserved.'
# Licensed under the MIT License.

@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'SdnDiagnostics.psm1'

    # Author of this module
    Author = 'Adam Rudell, Luyao Feng'

    # Company or vendor of this module
    CompanyName = 'Microsoft Corporation'

    # Copyright statement for this module
    Copyright = '(c) Microsoft Corporation. All rights reserved.'

    # ID used to uniquely identify this module
    GUID = 'c6cd3002-c6b1-4798-b532-2f939f527599'

    # Description of the functionality provided by this module
    Description = 'SdnDiagnostics is a tool used to simplify the data collection and diagnostics of Windows Software Defined Networking.'

    # Version number of this module.
    ModuleVersion = '0.0.0.0'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules = @(
        'modules\SdnDiag.Common.psm1'
        'modules\SdnDiag.Gateway.Health.psm1'
        'modules\SdnDiag.Gateway.psm1'
        'modules\SdnDiag.Health.psm1'
        'modules\SdnDiag.LoadBalancerMux.psm1'
        'modules\SdnDiag.LoadBalancerMux.Health.psm1'
        'modules\SdnDiag.NetworkController.psm1'
        'modules\SdnDiag.NetworkController.Health.psm1'
        'modules\SdnDiag.NetworkController.FC.psm1'
        'modules\SdnDiag.NetworkController.SF.psm1'
        'modules\SdnDiag.NetworkController.SF.Health.psm1'
        'modules\SdnDiag.Server.psm1'
        'modules\SdnDiag.Server.Health.psm1'
        'modules\SdnDiag.Utilities.psm1'
        'modules\Test-SdnExpressBgp.psm1'
    )

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @()

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Functions to export from this module
    FunctionsToExport = @(
        'Clear-SdnWorkingDirectory',
        'Copy-SdnFileFromComputer',
        'Copy-SdnFileToComputer',
        'Convert-SdnEtwTraceToTxt',
        'Debug-SdnFabricInfrastructure',
        'Debug-SdnGateway',
        'Debug-SdnLoadBalancerMux',
        'Debug-SdnNetworkController',
        'Debug-SdnServer',
        'Disable-SdnRasGatewayTracing',
        'Enable-SdnRasGatewayTracing',
        'Enable-SdnVipTrace'
        'Get-SdnAuditLog',
        'Get-SdnApiEndpoint'
        'Get-SdnCertificate',
        'Get-SdnConfigState',
        'Get-SdnDiagnosticLogFile',
        'Get-SdnEventLog',
        'Get-SdnFabricInfrastructureResult',
        'Get-SdnGateway',
        'Get-SdnInfrastructureInfo',
        'Get-SdnInternalLoadBalancer',
        'Get-SdnModuleConfiguration',
        'Get-SdnMuxCertificate',
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
        'Get-SdnNetworkControllerNode',
        'Get-SdnNetworkControllerNodeCertificate'
        'Get-SdnNetworkControllerRestCertificate',
        'Get-SdnNetworkControllerState',
        'Get-SdnOvsdbAddressMapping',
        'Get-SdnOvsdbFirewallRule',
        'Get-SdnOvsdbGlobalTable',
        'Get-SdnOvsdbPhysicalPort',
        'Get-SdnOvsdbRouterTable',
        'Get-SdnOvsdbUcastMacRemoteTable',
        'Get-SdnProviderAddress',
        'Get-SdnPublicIPPoolUsageSummary',
        'Get-SdnResource',
        'Get-SdnServer',
        'Get-SdnServerCertificate',
        'Get-SdnServiceFabricApplication',
        'Get-SdnServiceFabricApplicationHealth',
        'Get-SdnServiceFabricClusterConfig',
        'Get-SdnServiceFabricClusterHealth',
        'Get-SdnServiceFabricClusterManifest',
        'Get-SdnServiceFabricNode',
        'Get-SdnServiceFabricPartition',
        'Get-SdnServiceFabricReplica',
        'Get-SdnServiceFabricService',
        'Get-SdnSlbStateInformation',
        'Get-SdnVipConfig',
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
        'New-SdnExpressBgpHost',
        'New-SdnMuxCertificate',
        'New-SdnNetworkControllerNodeCertificate',
        'New-SdnNetworkControllerRestCertificate',
        'New-SdnServerCertificate',
        'Remove-SdnExpressBgpHost',
        'Repair-SdnDiagnosticsScheduledTask',
        'Set-SdnCertificateAcl',
        'Set-SdnNetworkController',
        'Set-SdnResource',
        'Set-SdnServiceFabricClusterConfig',
        'Set-SdnVMNetworkAdapterPortProfile',
        'Show-SdnVfpPortConfig',
        'Show-SdnVipState',
        'Start-SdnCertificateRotation',
        'Start-SdnDataCollection',
        'Start-SdnEtwTraceCapture',
        'Start-SdnMuxCertificateRotation',
        'Start-SdnServerCertificateRotation',
        'Start-SdnNetshTrace',
        'Stop-SdnEtwTraceCapture',
        'Stop-SdnNetshTrace',
        'Test-SdnCertificateRotationConfig',
        'Test-SdnExpressBGP',
        'Test-SdnProviderAddressConnectivity'
    )

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @(
        'Get-SdnEnvironmentInfo'
    )

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @(
                'MSFTNet','Microsoft','Windows','Network','Networking','SDN','Diagnostics'
            )

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/microsoft/SdnDiagnostics'

            # A URL to the license for this module.
            LicenseUri = 'https://microsoft.mit-license.org/'

            # External dependent modules of this module
            ExternalModuleDependencies = @(
                'CimCmdlets', 'DnsClient', 'Microsoft.PowerShell.Archive', 'NetSecurity', 'NetTCPIP', 'SmbShare'
            )
        }
    }
}
