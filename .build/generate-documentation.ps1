<#
    .SYNOPSIS
        Builds the markdown documentation for the module.
    .DESCRIPTION
        Builds the markdown documentation for the module using the PlatyPS PowerShell module, generating one
        markdown page per exported function. When -WikiPath is specified, the generated documentation is also
        synchronized into the provided wiki checkout, matching the SdnDiagnostics.wiki repository structure:
          - Function pages are copied/overwritten into a `functions\` subfolder of the wiki.
          - Function pages for functions that no longer exist are removed from `functions\`.
          - The `## Functions` section of `_SideBar.md` is regenerated with a link to every exported function.
            Any hand-authored content above the `## Functions` heading (e.g. Home, How To Guides,
            Troubleshooting, Learning sections) is preserved as-is.
        Other hand-authored wiki pages (e.g. Home.md) are never touched.
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

if($WikiPath){
    if(-NOT (Test-Path -Path $WikiPath -PathType Container)){
        throw "WikiPath '$WikiPath' does not exist or is not a directory."
    }

    "Synchronizing generated documentation into wiki path '{0}'" -f $WikiPath | Write-Host

    # mirrors the SdnDiagnostics.wiki repository structure, where function pages live under a
    # `functions\` subfolder alongside other hand-authored top-level wiki pages
    $wikiFunctionsPath = Join-Path -Path $WikiPath -ChildPath "functions"
    if(-NOT (Test-Path -Path $wikiFunctionsPath -PathType Container)) {
        $null = New-Item -Path $wikiFunctionsPath -ItemType Directory -Force
    }

    # approved verbs are used to identify previously-generated function pages so that hand-authored
    # wiki pages are never touched or removed by this sync
    $approvedVerbs = (Get-Verb).Verb
    $verbPattern = "^($($approvedVerbs -join '|'))-"

    $exportedFunctionNames = $exportedFunctions.Name
    $existingWikiFunctionDocs = Get-ChildItem -Path "$wikiFunctionsPath\*" -Include *.md | Where-Object { $_.BaseName -match $verbPattern }
    $staleWikiFunctionDocs = $existingWikiFunctionDocs | Where-Object { $_.BaseName -inotin $exportedFunctionNames }
    if($staleWikiFunctionDocs){
        "Removing {0} stale function page(s) from wiki" -f $staleWikiFunctionDocs.Count | Write-Host
        $staleWikiFunctionDocs | Remove-Item -Force
    }

    Get-ChildItem -Path "$docPath\*" -Include *.md | Copy-Item -Destination $wikiFunctionsPath -Force

    # regenerate only the "## Functions" section of _SideBar.md, preserving any hand-authored
    # content (Home, How To Guides, Troubleshooting Guides, Learning, etc.) above that heading
    "Updating wiki sidebar" | Write-Host
    $sideBarWikiPath = Join-Path -Path $WikiPath -ChildPath "_SideBar.md"
    $functionsHeadingPattern = '^#+\s*Functions\s*$'

    $prefixLines = [System.Collections.Generic.List[string]]::new()
    if(Test-Path -Path $sideBarWikiPath -PathType Leaf) {
        $existingSideBarLines = @(Get-Content -Path $sideBarWikiPath)
        $headingIndex = -1
        for($i = 0; $i -lt $existingSideBarLines.Count; $i++){
            if($existingSideBarLines[$i] -match $functionsHeadingPattern){
                $headingIndex = $i
                break
            }
        }

        if($headingIndex -ge 0){
            if($headingIndex -gt 0){
                $prefixLines.AddRange([string[]]$existingSideBarLines[0..($headingIndex - 1)])
            }
        }
        else {
            $prefixLines.AddRange([string[]]$existingSideBarLines)
        }
    }
    else {
        "No existing _SideBar.md found at wiki root; creating a new one" | Write-Host -ForegroundColor:Yellow
    }

    $newSideBarContent = [System.Collections.Generic.List[string]]::new()
    $newSideBarContent.AddRange($prefixLines)
    if($newSideBarContent.Count -gt 0 -and $newSideBarContent[$newSideBarContent.Count - 1] -ne ''){
        $newSideBarContent.Add('')
    }
    $newSideBarContent.Add('## Functions')
    foreach($function in $exportedFunctions){
        $newSideBarContent.Add("- [$($function.Name)]($($function.Name))")
    }

    $newSideBarContent | Set-Content -Path $sideBarWikiPath -Force
}
