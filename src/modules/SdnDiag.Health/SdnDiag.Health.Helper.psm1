# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

enum SdnHealthResult {
    PASS
    FAIL
    WARNING
}

class SdnHealth {
    [String]$Name = (Get-PSCallStack)[1].Command
    [SdnHealthResult]$Result = 'PASS'
    [DateTime]$OccurrenceTime = [System.DateTime]::UtcNow
    [Object]$Properties
    [String[]]$Remediation
}

class SdnFabricEnvObject {
    [String[]]$ComputerName
    [Uri]$NcUrl
    [Object]$Role
    [Object]$EnvironmentInfo
}

class SdnFabricHealthReport {
    [DateTime]$OccurrenceTime = [System.DateTime]::UtcNow
    [String]$Role
    [SdnHealthResult]$Result = 'PASS'
    [Object[]]$HealthValidation
}

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

        return $result.Name | Where-Object {$_.Name -like "*$wordToComplete*"} | Sort-Object
    }
}

Register-ArgumentCompleter -CommandName 'Get-SdnFabricInfrastructureResult' -ParameterName 'Role' -ScriptBlock $fabricInfraResultScriptBlock.Role
Register-ArgumentCompleter -CommandName 'Get-SdnFabricInfrastructureResult' -ParameterName 'Name' -ScriptBlock $fabricInfraResultScriptBlock.Name
