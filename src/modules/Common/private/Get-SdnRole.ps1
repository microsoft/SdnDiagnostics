# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnRole {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$ComputerName
    )

    if ($null -eq $Global:SdnDiagnostics.EnvironmentInfo) {
        throw New-Object System.NullReferenceException("Unable to enumerate data from EnvironmentInfo")
    }

    foreach ($role in ($Global:SdnDiagnostics.EnvironmentInfo.Keys | Where-Object {$_ -iin $Global:SdnDiagnostics.Config.Keys})) {
        if ($ComputerName -iin $Global:SdnDiagnostics.EnvironmentInfo[$role]) {
            return $role.ToString()
        }
    }
}
