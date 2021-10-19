# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnRoleConfiguration {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnRoles]$Role
    )

    return (Get-Content -Path "$PSScriptRoot\..\..\..\config\$Role\settings.json" | ConvertFrom-Json)
}
