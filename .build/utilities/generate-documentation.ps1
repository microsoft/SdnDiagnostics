<#
    .SYNOPSIS
        Builds the markdown documentation for the module.
    .DESCRIPTION
        Builds the markdown documentation for the module using the PlatyPS PowerShell module.
#>

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
$sideBarNav = "$PSScriptRoot\..\..\.documentation\_SideBar.md"

if(!(Test-Path -Path $docPath -PathType Container)){
    $null = New-Item -Path $docPath -ItemType Directory -Force
}

Import-Module -Name platyPS -Force
Import-Module -Name $modulePath -Force

# remove existing articles as this helps ensure any deprecated exported function does not get published
$oldArticles = Get-ChildItem -Path "$docPath\*" -Include *.md
if($oldArticles){
    "Removing existing documentation to ensure clean build" | Write-Host
    $oldArticles | Remove-Item -Force
}

# generate the latest markdown files
"Generating function documentation" | Write-Host
$null = New-MarkdownHelp -Module SdnDiagnostics -OutputFolder $docPath -NoMetadata -Force

$currentFiles = Get-ChildItem -Path $docPath\* -Include *.md
foreach($function in (Get-Command -Module SdnDiagnostics)){
    if($function.Name -inotin ($currentFiles).BaseName){
        "Documentation not generated for {0}" -f $function.Name | Write-Host -ForegroundColor:Yellow
    }
}

# generate the side bar navigation
"Generating side bar navigation" | Write-Host

$sideBarInto = @'
# Documentation
- [Home](Home)

## Functions
'@

$sideBarNavcontent = @()
$sideBarNavcontent += $sideBarInto

foreach($file in $currentFiles){
    $navLink = "- [{0}]({0})" -f $file.BaseName
    $sideBarNavcontent += $navLink
}

$sideBarNavcontent | Out-File -FilePath $sideBarNav -Encoding utf8



