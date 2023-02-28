# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnRoleConfiguration {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnRoles]$Role
    )

    return ($Global:SdnDiagnostics.Config[$Role])
}
