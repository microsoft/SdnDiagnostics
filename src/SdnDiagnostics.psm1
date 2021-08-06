# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. "$PSScriptRoot\config\app\settings.ps1"

# dot source the private scripts
foreach($item in (Get-ChildItem -Path "$PSScriptRoot\modules\private" -Include "*.ps1" -Recurse)){
    . $item.FullName
}

# dot source the public scripts
foreach($item in (Get-ChildItem -Path "$PSScriptRoot\modules\public" -Include "*.ps1" -Recurse)){
    . $item.FullName
}

$ErrorActionPreference = 'Continue'