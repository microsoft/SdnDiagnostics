# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# dot source the enums
foreach($item in (Get-ChildItem -Path "$PSScriptRoot\enum" -Recurse -Include "*.ps1")){
    . $item.FullName
}

# dot source the modules scripts
foreach($item in Get-ChildItem -Path "$PSScriptRoot\modules" -Recurse -Include "*.ps1"){
    . $item.FullName
}

# dot source the health scripts
foreach($item in Get-ChildItem -Path "$PSScriptRoot\health" -Recurse -Include "*.ps1"){
    . $item.FullName
}

# dot source the known issue scripts
foreach($item in Get-ChildItem -Path "$PSScriptRoot\knownIssues" -Recurse -Include "*.ps1"){
    . $item.FullName
}

. "$PSScriptRoot\config\settings.ps1"

$ErrorActionPreference = 'Continue'
