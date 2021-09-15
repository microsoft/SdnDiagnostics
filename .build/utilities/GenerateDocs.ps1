<#
    .SYNOPSIS
        Builds the markdown documentation for the module.
    .DESCRIPTION
        Builds the markdown documentation for the module using the PlatyPS PowerShell module.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [Switch]$Update
)

$ErrorActionPreference = "Stop"

$platyFromPoshGallery = Find-Module -Name platyPS
$platyFromLocal = Get-Module -ListAvailable -Name platyPS | Sort-Object Version -Descending | Select-Object -First 1

if($null -ne $platyFromLocal) {
    if([Version]$platyFromPoshGallery.Version -gt [Version]$platyFromLocal.Version){
        Install-Module -Name platyPS -Scope CurrentUser -Confirm:$false -Force
    }
}
else {
    Install-Module -Name platyPS -Scope CurrentUser -Confirm:$false -Force
}

$modulePath = "$PSScriptRoot\..\..\src\SdnDiagnostics.psd1"
$docPath = "$PSScriptRoot\..\..\.documentation"

Import-Module -Name platyPS -Force
Import-Module -Name $modulePath -Force

if($update){
    New-MarkdownHelp -Module SdnDiagnostics -OutputFolder $docPath
}
else {
    Update-MarkdownHelp -Path $docPath
}
