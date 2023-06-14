# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Import-Module $PSScriptRoot\SdnDiagnostics.Helper.psm1

if (Get-Module -Name 'test-sdnexpressbgp' -ErrorAction SilentlyContinue) {
    Remove-Module -Name 'test-sdnexpressbgp' -Force -ErrorAction SilentlyContinue
}
Import-Module "$PSScriptRoot\externalPackages\test-sdnexpressbgp.psd1" -Scope Global

New-Variable -Name 'SdnDiagnostics' -Scope 'Global' -Force -Value @{
    Cache = @{}
    EnvironmentInfo = @{
        RestApiVersion = 'V1'
    }
}
