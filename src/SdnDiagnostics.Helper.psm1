# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
}

$fabricNodeParamCommands = (
    'Invoke-Command',
    'Invoke-SdnCommand',
    'New-PSSession',
    'Enter-PSSession',
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
    'Get-SdnOvsdbFirewallRule',
    'Get-SdnOvsdbGlobalTable',
    'Get-SdnOvsdbPhysicalPort',
    'Get-SdnOvsdbUcastMacRemoteTable',
    'Get-SdnProviderAddress',
    'Get-SdnVfpVmSwitchPort',
    'Get-SdnVMNetworkAdapter'
)

Register-ArgumentCompleter -CommandName $serverParamCommands -ParameterName 'ComputerName' -ScriptBlock $scriptBlocks.ServerNodes

$fabricInfraResultScriptBlock = @{
    Role = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $result = (Get-SdnFabricInfrastructureResult)
        if ([string]::IsNullOrEmpty($wordToComplete)) {
            return ($result.Role | Sort-Object -Unique)
        }

        return $result.Role | Where-Object {$_.Role -like "*$wordToComplete*"} | Sort-Object
    }
    Name = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $result = (Get-SdnFabricInfrastructureResult).HealthValidation
        if ([string]::IsNullOrEmpty($wordToComplete)) {
            return ($result.Name | Sort-Object -Unique)
        }

        return $result.HealthValidation | Where-Object {$_.Name -like "*$wordToComplete*"} | Sort-Object
    }
}

Register-ArgumentCompleter -CommandName 'Get-SdnFabricInfrastructureResult' -ParameterName 'Role' -ScriptBlock $fabricInfraResultScriptBlock.Role
Register-ArgumentCompleter -CommandName 'Get-SdnFabricInfrastructureResult' -ParameterName 'Name' -ScriptBlock $fabricInfraResultScriptBlock.Name

