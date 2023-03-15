# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Using module .\..\SdnDiag.Common\SdnDiag.Common.Helper.psm1
Using module .\SdnDiag.Health.Helper.psm1

Import-Module $PSScriptRoot\SdnDiag.Health.Helper.psm1
Import-Module $PSScriptRoot\..\SdnDiag.Utilities\SdnDiag.Utilities.psm1

# create local variable to store configuration data
New-Variable -Name 'SdnDiagnostics_Health' -Scope 'Script' -Force -Value @{
    Cache = @{}
}


##### FUNCTIONS AUTO-POPULATED BELOW THIS LINE DURING BUILD #####
