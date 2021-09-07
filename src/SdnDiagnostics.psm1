# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. "$PSScriptRoot\config\app\settings.ps1"

# dot source the modules scripts
$modules = @(
    'private\common'
    'private\dataCollection'
    'private\networkController'
    'private\server'
    'private\softwareLoadBalancer'
    'private\utilities'
    'public\DataCollection'
    'public\Gateway'
    'public\NetworkController'
    'public\NetworkController.ServiceFabric'
    'public\Server'
    'public\SoftwareLoadBalancer'
    'public\Tracing'
    'public\Utilities'
)

foreach($item in $modules){
    . ("{0}\{1}.ps1" -f "$PSScriptRoot\modules", $item)
}


# dot source the health scripts
$healthValidations = @(
    'Gateway\Test-SdnGatewayConfigState'
    'Gateway\Test-SdnGatewayServiceState'
    'LoadBalancerMuxes\Test-SdnLoadBalancerMuxConfigState'
    'LoadBalancerMuxes\Test-SdnLoadBalancerMuxServiceState'
    'NetworkController\Test-NetworkControllerServiceState'
    'Server\Test-SdnEncapOverhead'
    'Server\Test-SdnProviderNetwork'
    'Server\Test-SdnServerConfigState'
    'Server\Test-SdnServerServiceState'
    'Debug-SdnFabricInfrastructure'
)

foreach($item in $healthValidations){
    . ("{0}\{1}.ps1" -f "$PSScriptRoot\health", $item)
}

# dot source the known issue scripts
$knownIssues = @(
    'common'
    'Test-SdnKINetworkInterfaceAPIDuplicateMacAddress'
    'Test-SdnKINetworkInterfacePlacement'
    'Test-SdnKIServiceFabricPartitionDatabaseSize'  
    'Test-SdnKIVfpDuplicatePort'
    'Test-SdnKIVMNetAdapterDuplicateMacAddress'
    'Test-SdnKnownIssue'
)

foreach($item in $knownIssues){
    . ("{0}\{1}.ps1" -f "$PSScriptRoot\knownIssues", $item)
}

$ErrorActionPreference = 'Continue'