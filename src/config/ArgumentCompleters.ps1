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

    SoftwareLoadBalancerNodes = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $computerName = $Global:SdnDiagnostics.EnvironmentInfo.SoftwareLoadBalancer

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
}

Register-ArgumentCompleter -CommandName Invoke-Command -ParameterName 'ComputerName' -ScriptBlock $scriptBlocks.AllFabricNodes
Register-ArgumentCompleter -CommandName 'Get-SdnKnownIssue' -ParameterName 'Name' -ScriptBlock $scriptBlocks.KnownIssueTests
Register-ArgumentCompleter -CommandName 'Get-SdnFabricInfrastructureHealth' -ParameterName 'Name' -ScriptBlock $scriptBlocks.FabricHealthTests

$networkControllerParamCommands = (
    'Debug-SdnFabricInfrastructure',
    'Test-SdnKnownIssue',
    'Start-SdnDataCollection',
    'Get-SdnNetworkController',
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

