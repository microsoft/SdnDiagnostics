# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnCache {
    param (
        [System.String]$Name
    )

    return $Global:SdnDiagnostics.Cache[$Name]
}
