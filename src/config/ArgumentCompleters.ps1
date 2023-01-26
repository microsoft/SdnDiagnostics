$scriptBlocks = @{
    AllFabricNodes = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $computerName = $Global:SdnDiagnostics.EnvironmentInfo.FabricNodes

        if ([string]::IsNullOrEmpty($wordToComplete)) {
            return ($computerName | Sort-Object)
        }

        return $computerName | Where-Object {$_ -like "*$wordToComplete*"} | Sort-Object
    }

    GatewayNodes = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $computerName = $Global:SdnDiagnostics.EnvironmentInfo.Gateway

        if ([string]::IsNullOrEmpty($wordToComplete)) {
            return ($computerName | Sort-Object)
        }

        return $computerName | Where-Object {$_ -like "*$wordToComplete*"} | Sort-Object
    }

    NetworkControllerNodes = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $computerName = $Global:SdnDiagnostics.EnvironmentInfo.NetworkController

        if ([string]::IsNullOrEmpty($wordToComplete)) {
            return ($computerName | Sort-Object)
        }

        return $computerName | Where-Object {$_ -like "*$wordToComplete*"} | Sort-Object
    }

    ServerNodes = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $computerName = $Global:SdnDiagnostics.EnvironmentInfo.Server

        if ([string]::IsNullOrEmpty($wordToComplete)) {
            return ($computerName | Sort-Object)
        }

        return $computerName | Where-Object {$_ -like "*$wordToComplete*"} | Sort-Object
    }

    LoadBalancerMuxNodes = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $computerName = $Global:SdnDiagnostics.EnvironmentInfo.LoadBalancerMux

        if ([string]::IsNullOrEmpty($wordToComplete)) {
            return ($computerName | Sort-Object)
        }

        return $computerName | Where-Object {$_ -like "*$wordToComplete*"} | Sort-Object
    }

    FabricHealthTests = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $testName = ($Global:SdnDiagnostics.Cache.FabricHealth).Name

        if ([string]::IsNullOrEmpty($wordToComplete)) {
            return ($testName | Sort-Object)
        }

        return $testName | Where-Object {$_ -like "*$wordToComplete*"} | Sort-Object
    }

    KnownIssueTests = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $testName = ($Global:SdnDiagnostics.Cache.KnownIssues).Name

        if ([string]::IsNullOrEmpty($wordToComplete)) {
            return ($testName | Sort-Object)
        }

        return $testName | Where-Object {$_ -like "*$wordToComplete*"} | Sort-Object
    }

    ServiceFabricServiceName = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $serviceName = @(
            'fabric:/NetworkController/ApiService'
            'fabric:/NetworkController/BackupRestore'
            'fabric:/NetworkController/ControllerService'
            'fabric:/NetworkController/FirewallService'
            'fabric:/NetworkController/FnmService'
            'fabric:/NetworkController/GatewayManager'
            'fabric:/NetworkController/HelperService'
            'fabric:/NetworkController/ServiceInsertion'
            'fabric:/NetworkController/SlbManagerService'
            'fabric:/NetworkController/UpdateService'
            'fabric:/NetworkController/VSwitchService'
        )

        if ([string]::IsNullOrEmpty($wordToComplete)) {
            return ($serviceName | Sort-Object)
        }
    }

    ServiceFabricServiceTypeName = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $serviceTypeName = @(
            'ApiService'
            'BackupRestore'
            'ControllerService'
            'FirewallService'
            'FnmService'
            'GatewayManager'
            'HelperService'
            'ServiceInsertion'
            'SlbManagerService'
            'UpdateService'
            'VSwitchService'
        )

        if ([string]::IsNullOrEmpty($wordToComplete)) {
            return ($serviceTypeName | Sort-Object)
        }
    }
}

Register-ArgumentCompleter -CommandName 'Get-SdnKnownIssue' -ParameterName 'Name' -ScriptBlock $scriptBlocks.KnownIssueTests
Register-ArgumentCompleter -CommandName 'Get-SdnFabricInfrastructureHealth' -ParameterName 'Name' -ScriptBlock $scriptBlocks.FabricHealthTests

$fabricNodeParamCommands = (
    'Invoke-Command',
    'Invoke-SdnCommand',
    'Start-SdnDataCollection',
    'Start-SdnNetshTrace',
    'Stop-SdnNetshTrace'
)

Register-ArgumentCompleter -CommandName $fabricNodeParamCommands -ParameterName 'ComputerName' -ScriptBlock $scriptBlocks.AllFabricNodes

$networkControllerParamCommands = (
    'Debug-SdnFabricInfrastructure',
    'Test-SdnKnownIssue',
    'Start-SdnDataCollection',
    'Get-SdnNetworkController',
    'Get-SdnNetworkControllerNode',
    'Get-SdnNetworkControllerClusterInfo',
    'Get-SdnNetworkControllerState',
    'Get-SdnServiceFabricApplicationHealth',
    'Get-SdnServiceFabricClusterHealth',
    'Get-SdnServiceFabricClusterManifest',
    'Get-SdnServiceFabricNode',
    'Get-SdnServiceFabricReplica',
    'Get-SdnServiceFabricService',
    'Invoke-SdnServiceFabricCommand',
    'Move-SdnServiceFabricReplica'
)

Register-ArgumentCompleter -CommandName $networkControllerParamCommands -ParameterName 'NetworkController' -ScriptBlock $scriptBlocks.NetworkControllerNodes

$serverParamCommands = (
    'Get-SdnOvsdbAddressMapping',
    'Get-SdnOvsdbFirewallRuleTable',
    'Get-SdnOvsdbGlobalTable',
    'Get-SdnOvsdbPhysicalPortTable',
    'Get-SdnOvsdbUcastMacRemoteTable',
    'Get-SdnProviderAddress',
    'Get-SdnVfpVmSwitchPort',
    'Get-SdnVMNetworkAdapter'
)

Register-ArgumentCompleter -CommandName $serverParamCommands -ParameterName 'ComputerName' -ScriptBlock $scriptBlocks.ServerNodes

# argument completers for service fabric cmdlets
Register-ArgumentCompleter -CommandName 'Get-SdnServiceFabricReplica' -ParameterName 'ServiceName' -ScriptBlock $scriptBlocks.ServiceFabricServiceName
Register-ArgumentCompleter -CommandName 'Get-SdnServiceFabricReplica' -ParameterName 'ServiceTypeName' -ScriptBlock $scriptBlocks.ServiceFabricServiceTypeName

Register-ArgumentCompleter -CommandName 'Get-SdnServiceFabricService' -ParameterName 'ServiceName' -ScriptBlock $scriptBlocks.ServiceFabricServiceName
Register-ArgumentCompleter -CommandName 'Get-SdnServiceFabricService' -ParameterName 'ServiceTypeName' -ScriptBlock $scriptBlocks.ServiceFabricServiceTypeName

Register-ArgumentCompleter -CommandName 'Get-SdnServiceFabricPartition ' -ParameterName 'ServiceName' -ScriptBlock $scriptBlocks.ServiceFabricServiceName
Register-ArgumentCompleter -CommandName 'Get-SdnServiceFabricPartition' -ParameterName 'ServiceTypeName' -ScriptBlock $scriptBlocks.ServiceFabricServiceTypeName


