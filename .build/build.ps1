$currentErrorPref = $ErrorActionPreference
$ErrorActionPreference = 'Stop'

& '.build\generate-version.ps1'
& '.\.build\clean.ps1'

function Get-ModuleVersion {
    # this is set in a prior step from generateVersion-ps.ps1    
    return $env:SdnDiagCustomBuildNumber
}

$outDir = "$PSScriptRoot\..\out\build"
if(!(Test-Path -Path $outDir)) {
    $null = New-Item -ItemType:Directory -Path $outDir -Force
}

Copy-Item "$PSScriptRoot\..\src" -Destination "$outDir\SdnDiagnostics" -Exclude "*.md" -Recurse -Force
& $PSScriptRoot\restore.ps1 -DestinationFolder "$outDir\SdnDiagnostics"

# setting the version of the module manifest
$modManifest = Get-ChildItem "$outDir\SdnDiagnostics" -Filter "*.psd1"
if(($null -ne (Get-Item "$($modManifest.DirectoryName)\$($modManifest.BaseName).psm1" -ErrorAction SilentlyContinue))) {
    try {
        $modVersion = Get-ModuleVersion
        $manifest = Test-ModuleManifest -Path $modManifest.FullName

        if($manifest.Version.ToString() -ne $modVersion) {
            "`r`nUpdating {0} version: {1} --> {2}" -f $modManifest.BaseName, $manifest.Version.ToString(), $modVersion | Write-Host
            Update-ModuleManifest -ModuleVersion $modVersion -Path $modManifest.FullName
            continue
        }
        
        "`r`n{0} version does not need to be updated." -f $modVersion | Write-Host
    }
    catch {
        "Failed to update the module manifest for $($modManifest.BaseName)" | Write-Error
        exit 1
    }
}

# lets try to import the module before proceeding. If there is a missing comma or syntax error in the psd1 we will fail
$moduleManifest = Join-Path -Path $outDir -ChildPath "SDNDiagnostics\SDNDiagnostics.psd1"
Import-Module $moduleManifest -ArgumentList @($true,$true) -ErrorAction:SilentlyContinue

if(!$?){
    $Error | Out-String | Write-Error
}

$ErrorActionPreference = $currentErrorPref