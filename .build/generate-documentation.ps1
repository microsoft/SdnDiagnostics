<#
    .SYNOPSIS
        Builds the markdown documentation for the module.
    .DESCRIPTION
        Builds the markdown documentation for the module using the PlatyPS PowerShell module. Generates one
        markdown page per exported function plus a _Sidebar.md for navigation. When -WikiPath is specified,
        the generated documentation is also synchronized into the provided wiki checkout: exported function
        pages are copied/overwritten, and function pages for functions that no longer exist are removed. Any
        other hand-authored wiki pages (e.g. Home.md) are left untouched.
    .PARAMETER WikiPath
        Path to a local checkout of the project's GitHub wiki repository (e.g. a checkout of
        microsoft/SdnDiagnostics.wiki). When specified, generated documentation is synchronized into this path.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [System.String]$WikiPath
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

$modulePath = "$PSScriptRoot\..\src\SdnDiagnostics.psd1"
$docPath = "$PSScriptRoot\..\.documentation\functions"
$sideBarPath = "$PSScriptRoot\..\.documentation\_Sidebar.md"

if(-NOT (Test-Path -Path $docPath -PathType Container)) {
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

$exportedFunctions = Get-Command -Module SdnDiagnostics | Sort-Object -Property Name
$currentFiles = Get-ChildItem -Path $docPath\* -Include *.md
foreach($function in $exportedFunctions){
    if($function.Name -inotin ($currentFiles).BaseName){
        "Documentation not generated for {0}" -f $function.Name | Write-Host -ForegroundColor:Yellow
    }
}

# generate a sidebar so the wiki has consistent navigation to each function page
"Generating wiki sidebar" | Write-Host
$sideBarContent = [System.Collections.Generic.List[string]]::new()
$sideBarContent.Add('# SdnDiagnostics')
$sideBarContent.Add('')
$sideBarContent.Add('[Home](Home)')
$sideBarContent.Add('')
$sideBarContent.Add('## Functions')
foreach($function in $exportedFunctions){
    $sideBarContent.Add("- [$($function.Name)]($($function.Name))")
}
$sideBarContent | Set-Content -Path $sideBarPath -Force

if($WikiPath){
    if(-NOT (Test-Path -Path $WikiPath -PathType Container)){
        throw "WikiPath '$WikiPath' does not exist or is not a directory."
    }

    "Synchronizing generated documentation into wiki path '{0}'" -f $WikiPath | Write-Host

    # approved verbs are used to identify previously-generated function pages so that hand-authored
    # wiki pages (e.g. Home.md) are never touched or removed by this sync
    $approvedVerbs = (Get-Verb).Verb
    $verbPattern = "^($($approvedVerbs -join '|'))-"

    $exportedFunctionNames = $exportedFunctions.Name
    $existingWikiFunctionDocs = Get-ChildItem -Path "$WikiPath\*" -Include *.md | Where-Object { $_.BaseName -match $verbPattern }
    $staleWikiFunctionDocs = $existingWikiFunctionDocs | Where-Object { $_.BaseName -inotin $exportedFunctionNames }
    if($staleWikiFunctionDocs){
        "Removing {0} stale function page(s) from wiki" -f $staleWikiFunctionDocs.Count | Write-Host
        $staleWikiFunctionDocs | Remove-Item -Force
    }

    Get-ChildItem -Path "$docPath\*" -Include *.md | Copy-Item -Destination $WikiPath -Force
    Copy-Item -Path $sideBarPath -Destination $WikiPath -Force
}
