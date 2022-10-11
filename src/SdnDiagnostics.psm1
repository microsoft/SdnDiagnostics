# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# ensure that the module is running as local administrator
$elevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-NOT $elevated) {
  throw New-Object System.Exception("This module requires elevated permissions. Run PowerShell as Administrator and import the module again.")
}

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
. "$PSScriptRoot\config\ArgumentCompleters.ps1"

$ErrorActionPreference = 'Continue'
