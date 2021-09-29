# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

New-Variable -Name SdnDiagnostics -Scope Global -Force -Value @{
    Cache = @{}
    Config = @{
        Host = (Get-SdnRoleConfiguration -Role:Server)
        Gateway = (Get-SdnRoleConfiguration -Role:Gateway)
        NC = (Get-SdnRoleConfiguration -Role:NetworkController)
        SLB = (Get-SdnRoleConfiguration -Role:SoftwareLoadBalancer)
    }
    Credential = $null
    EnvironmentInfo = @{
        RestApiVersion = 'V1'
    }
    NcRestCredential = $null
    Settings = (Get-Content -Path "$PSScriptRoot\settings.json" | ConvertFrom-Json)
    TraceFilePath = $null
}
