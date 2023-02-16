# Module manifest for diagnostics for Software Defined Networking.
#
# Copyright='© Microsoft Corporation. All rights reserved.'
# Licensed under the MIT License.

@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'SdnDiag.NetworkController.psm1'

    # Author of this module
    Author = 'Adam Rudell'

    # Company or vendor of this module
    CompanyName = 'Microsoft Corporation'

    # Copyright statement for this module
    Copyright = '(c) Microsoft Corporation. All rights reserved.'

    # Version number of this module.
    ModuleVersion = '1.0.0.0'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules = @(
        'SdnDiag.NetworkController.RotateCert.psm1'
        'SdnDiag.NetworkController.ServiceFabric.psm1'
    )

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @()

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Functions to export from this module
    FunctionsToExport = @(
        'Get-SdnApiEndpoint'
        'Get-SdnAuditLog'
        'Get-SdnDiscovery'
        'Get-SdnGateway'
        'Get-SdnInfrastructureInfo'
        'Get-SdnLoadBalancerMux'
        'Get-SdnNetworkController'
        'Get-SdnNetworkControllerConfigurationState'
        'Get-SdnNetworkControllerInfoOffline'
        'Get-SdnNetworkControllerNode'
        'Get-SdnNetworkControllerNodeCertificate'
        'Get-SdnNetworkControllerRestCertificate'
        'Get-SdnNetworkControllerRestURL'
        'Get-SdnNetworkControllerState'
        'Get-SdnResource'
        'Get-SdnServer'
        'Get-SdnServiceFabricApplicationHealth'
        'Get-SdnServiceFabricClusterConfig'
        'Get-SdnServiceFabricClusterHealth'
        'Get-SdnServiceFabricClusterManifest'
        'Get-SdnServiceFabricLog'
        'Get-SdnServiceFabricNode'
        'Get-SdnServiceFabricPartition'
        'Get-SdnServiceFabricReplica'
        'Get-SdnServiceFabricService'
        'Get-SdnVirtualServer'
        'Invoke-SdnNetworkControllerStateDump'
        'Invoke-SdnResourceDump'
        'Invoke-SdnServiceFabricCommand'
        'Move-SdnServiceFabricReplica'
        'Start-SdnDataCollection'
    )

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @()

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/microsoft/SdnDiagnostics'

            # A URL to the license for this module.
            LicenseUri = 'https://microsoft.mit-license.org/'

            # External dependent modules of this module
            ExternalModuleDependencies = @(
                'Microsoft.PowerShell.Archive'
            )
        }
    }
}
