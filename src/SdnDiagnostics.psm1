# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

$enum = @(
    'enum\NcAppServices.ps1'
    'enum\NcManagedRoles.ps1'
    'enum\OvsdbTable.ps1'
    'enum\SdnApiResource.ps1'
    'enum\SdnRoles.ps1'
    'enum\TraceLevel.ps1'
    'enum\VMState.ps1'
)
foreach($item in $enum){
    . ("{0}\{1}" -f "$PSScriptRoot", $item)
}


# dot source the modules scripts
$modules = @(
    'Common\private\Export-RegistryKeyConfigDetails.ps1'
    'Common\private\Get-GeneralConfigurationState.ps1'
    'Common\private\Get-SdnApiEndpoint.ps1'
    'Common\private\Get-SdnRoleConfiguration.ps1'
    'Common\public\Get-SdnDiagnosticLog.ps1'
    'Common\public\Get-SdnEventLog.ps1'
    'Common\public\Invoke-SdnGetNetView.ps1'
    'Common\public\Start-SdnDataCollection.ps1'
    'Gateway\public\Disable-RasGatewayTracing.ps1'
    'Gateway\public\Enable-RasGatewayTracing.ps1'
    'Gateway\public\Get-SdnGatewayConfigurationState.ps1'
    'NetworkController\private\Get-SdnVirtualServer.ps1'
    'NetworkController\private\Invoke-SdnNetworkControllerStateDump.ps1'
    'NetworkController\public\Get-SdnApiResource.ps1'
    'NetworkController\public\Get-SdnGateway.ps1'
    'NetworkController\public\Get-SdnInfrastructureInfo.ps1'
    'NetworkController\public\Get-SdnLoadBalancerMux.ps1'
    'NetworkController\public\Get-SdnNetworkController.ps1'
    'NetworkController\public\Get-SdnNetworkControllerConfigurationState.ps1'
    'NetworkController\public\Get-SdnNetworkControllerState.ps1'
    'NetworkController\public\Get-SdnResource.ps1'
    'NetworkController\public\Get-SdnServer.ps1'
    'NetworkController\public\Get-SdnServiceFabricApplicationHealth.ps1'
    'NetworkController\public\Get-SdnServiceFabricClusterHealth.ps1'
    'NetworkController\public\Get-SdnServiceFabricClusterManifest.ps1'
    'NetworkController\public\Get-SdnServiceFabricLog.ps1'
    'NetworkController\public\Get-SdnServiceFabricNode.ps1'
    'NetworkController\public\Get-SdnServiceFabricReplica.ps1'
    'NetworkController\public\Get-SdnServiceFabricService.ps1'
    'NetworkController\public\Invoke-SdnServiceFabricCommand.ps1'
    'NetworkController\public\Move-SdnServiceFabricReplica.ps1'
    'Server\private\Get-OvsdbDatabase.ps1'
    'Server\public\Get-NetworkInterfaceEncapOverheadSetting.ps1'
    'Server\public\Get-OvsdbAddressMapping.ps1'
    'Server\public\Get-OvsdbFirewallRuleTable.ps1'
    'Server\public\Get-OvsdbGlobalTable.ps1'
    'Server\public\Get-OvsdbPhysicalPortTable.ps1'
    'Server\public\Get-OvsdbUcastMacRemoteTable.ps1'
    'Server\public\Get-SdnOvsdbAddressMapping.ps1'
    'Server\public\Get-SdnOvsdbFirewallRuleTable.ps1'
    'Server\public\Get-SdnOvsdbGlobalTable.ps1'
    'Server\public\Get-SdnOvsdbPhysicalPortTable.ps1'
    'Server\public\Get-SdnOvsdbUcastMacRemoteTable.ps1'
    'Server\public\Get-SdnProviderAddress.ps1'
    'Server\public\Get-SdnServerConfigurationState.ps1'
    'Server\public\Get-SdnVfpVmSwitchPort.ps1'
    'Server\public\Get-SdnVMNetworkAdapter.ps1'
    'Server\public\Get-VfpPortGroup.ps1'
    'Server\public\Get-VfpPortLayer.ps1'
    'Server\public\Get-VfpPortRule.ps1'
    'Server\public\Get-VfpVMSwitchPort.ps1'
    'Server\public\Get-VMNetworkAdapterPortProfile.ps1'
    'Server\public\Test-SdnProviderAddressConnectivity.ps1'
    'SoftwareLoadBalancer\private\Get-PublicIpReference.ps1'
    'SoftwareLoadBalancer\public\Get-SdnNetworkInterfaceOutboundPublicIPAddress.ps1'
    'SoftwareLoadBalancer\public\Get-SdnSlbMuxConfigurationState.ps1'
    'SoftwareLoadBalancer\public\Get-SdnSlbStateInformation.ps1'
    'Tracing\private\Get-TraceProviders.ps1'
    'Tracing\private\Start-EtwTraceSession.ps1'
    'Tracing\private\Stop-EtwTraceSession.ps1'
    'Tracing\public\Convert-EtwTraceToTxt.ps1'
    'Tracing\public\Start-EtwTraceCapture.ps1'
    'Tracing\public\Start-NetshTrace.ps1'
    'Tracing\public\Stop-EtwTraceCapture.ps1'
    'Tracing\public\Stop-NetshTrace.ps1'
    'Utilities\private\Confirm-RequiredFeaturesInstalled.ps1'
    'Utilities\private\Confirm-RequiredModulesLoaded.ps1'
    'Utilities\private\Confirm-UserInput.ps1'
    'Utilities\private\Copy-FileFromPSRemoteSession.ps1'
    'Utilities\private\Copy-FileToPSRemoteSession.ps1'
    'Utilities\private\Export-ObjectToFile.ps1'
    'Utilities\private\Format-MacAddressNoDashes.ps1'
    'Utilities\private\Format-MacAddressWithDashes.ps1'
    'Utilities\private\Format-NetshTraceProviderAsString.ps1'
    'Utilities\private\Get-FormattedDateTimeUTC.ps1'
    'Utilities\private\Get-FunctionFromFile.ps1'
    'Utilities\private\Get-TraceOutputFile.ps1'
    'Utilities\private\Get-WorkingDirectory.ps1'
    'Utilities\private\Invoke-PSRemoteCommand.ps1'
    'Utilities\private\New-PSRemotingSession.ps1'
    'Utilities\private\New-TraceOutputFile.ps1'
    'Utilities\private\New-WorkingDirectory.ps1'
    'Utilities\private\Remove-PSRemotingSession.ps1'
    'Utilities\private\Set-TraceOutputFile.ps1'
    'Utilities\private\Test-ComputerNameIsLocal.ps1'
    'Utilities\private\Test-Ping.ps1'
    'Utilities\private\Trace-Output.ps1'
    'Utilities\private\Wait-PSJob.ps1'
    'Utilities\public\Install-SdnDiagnostics.ps1'
)

foreach($item in $modules){
    . ("{0}\{1}" -f "$PSScriptRoot\modules", $item)
}


# dot source the health scripts
$healthValidations = @(
    'Gateway\Test-SdnGatewayConfigState.ps1'
    'Gateway\Test-SdnGatewayServiceState.ps1'
    'LoadBalancerMuxes\Test-SdnLoadBalancerMuxConfigState.ps1'
    'LoadBalancerMuxes\Test-SdnLoadBalancerMuxServiceState.ps1'
    'NetworkController\Test-NetworkControllerServiceState.ps1'
    'Server\Test-SdnEncapOverhead.ps1'
    'Server\Test-SdnProviderNetwork.ps1'
    'Server\Test-SdnServerConfigState.ps1'
    'Server\Test-SdnServerServiceState.ps1'
    'Debug-SdnFabricInfrastructure.ps1'
)

foreach($item in $healthValidations){
    . ("{0}\{1}" -f "$PSScriptRoot\health", $item)
}

# dot source the known issue scripts
$knownIssues = @(
    'private\Test-NetworkInterfaceLocation.ps1'
    'Test-SdnKINetworkInterfaceAPIDuplicateMacAddress.ps1'
    'Test-SdnKINetworkInterfacePlacement.ps1'
    'Test-SdnKIServerHostId.ps1'
    'Test-SdnKIServiceFabricPartitionDatabaseSize.ps1'  
    'Test-SdnKIVfpDuplicatePort.ps1'
    'Test-SdnKIVMNetAdapterDuplicateMacAddress.ps1'
    'Test-SdnKnownIssue.ps1'
)

foreach($item in $knownIssues){
    . ("{0}\{1}" -f "$PSScriptRoot\knownIssues", $item)
}

. "$PSScriptRoot\config\settings.ps1"

$ErrorActionPreference = 'Continue'