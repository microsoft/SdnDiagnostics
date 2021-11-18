# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# dot source the enums
foreach($item in (Get-ChildItem -Path "$PSScriptRoot\enum" -Recurse -Include "*.ps1")){
    . $item.FullName
}

# dot source the classes
foreach($item in (Get-ChildItem -Path "$PSScriptRoot\classes" -Recurse -Include "*.ps1")){
    . $item.FullName
}

# dot source the modules scripts
foreach($item in (Get-ChildItem -Path "$PSScriptRoot\modules" -Recurse -Include "*.ps1")){
    . $item.FullName
}

# dot source the insights
foreach($item in (Get-ChildItem -Path "$PSScriptRoot\insights" -Recurse -Include "*.ps1" | Where-Object { $_.DirectoryName -inotlike "*\insights\remediations*"})){
    . $item.FullName
}

. "$PSScriptRoot\config\settings.ps1"

$ErrorActionPreference = 'Continue'
