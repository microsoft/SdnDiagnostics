# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

$scriptBlocks = @{
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

        return $serviceName | Where-Object {$_ -ilike "*$wordToComplete*"} | Sort-Object
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

        return $serviceTypeName | Where-Object {$_ -ilike "*$wordToComplete*"} | Sort-Object
    }
}

Register-ArgumentCompleter -CommandName 'Get-SdnServiceFabricReplica' -ParameterName 'ServiceName' -ScriptBlock $scriptBlocks.ServiceFabricServiceName
Register-ArgumentCompleter -CommandName 'Get-SdnServiceFabricReplica' -ParameterName 'ServiceTypeName' -ScriptBlock $scriptBlocks.ServiceFabricServiceTypeName

Register-ArgumentCompleter -CommandName 'Get-SdnServiceFabricService' -ParameterName 'ServiceName' -ScriptBlock $scriptBlocks.ServiceFabricServiceName
Register-ArgumentCompleter -CommandName 'Get-SdnServiceFabricService' -ParameterName 'ServiceTypeName' -ScriptBlock $scriptBlocks.ServiceFabricServiceTypeName

Register-ArgumentCompleter -CommandName 'Get-SdnServiceFabricPartition' -ParameterName 'ServiceName' -ScriptBlock $scriptBlocks.ServiceFabricServiceName
Register-ArgumentCompleter -CommandName 'Get-SdnServiceFabricPartition' -ParameterName 'ServiceTypeName' -ScriptBlock $scriptBlocks.ServiceFabricServiceTypeName

Register-ArgumentCompleter -CommandName 'Move-SdnServiceFabricReplica' -ParameterName 'ServiceName' -ScriptBlock $scriptBlocks.ServiceFabricServiceName
Register-ArgumentCompleter -CommandName 'Move-SdnServiceFabricReplica' -ParameterName 'ServiceTypeName' -ScriptBlock $scriptBlocks.ServiceFabricServiceTypeName
