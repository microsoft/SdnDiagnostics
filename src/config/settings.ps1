# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

New-Variable -Name SdnDiagnostics -Scope Global -Force -Value @{
    Cache = @{}
    Config = @{
        Gateway = (Get-SdnRoleConfiguration -Role:Gateway)
        NetworkController = (Get-SdnRoleConfiguration -Role:NetworkController)
        Server = (Get-SdnRoleConfiguration -Role:Server)
        LoadBalancerMux = (Get-SdnRoleConfiguration -Role:LoadBalancerMux)
    }
    Credential = $null
    EnvironmentInfo = @{
        RestApiVersion = 'V1'
    }
    NcRestCredential = $null
    Settings = (Get-Content -Path "$PSScriptRoot\settings.json" | ConvertFrom-Json)
    TraceFilePath = $null
}
