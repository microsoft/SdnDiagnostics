param (
    [String]$Version
)

$currentErrorPref = $ErrorActionPreference
$ErrorActionPreference = 'Stop'


$outDir = "$PSScriptRoot\..\out\build"
if (-NOT (Test-Path -Path $outDir -PathType Container)) {
    $null = New-Item -ItemType:Directory -Path $outDir -Force
}

Copy-Item -Path "$PSScriptRoot\..\src" -Destination "$outDir\SdnDiagnostics" -Recurse -Force

# setting the version of the module manifest
$modManifest = Get-ChildItem "$outDir\SdnDiagnostics" -Filter "*.psd1"
if (($null -ne (Get-Item -Path "$($modManifest.DirectoryName)\$($modManifest.BaseName).psm1" -ErrorAction SilentlyContinue))) {
    try {
        $manifest = Test-ModuleManifest -Path $modManifest.FullName

        if ($manifest.Version.ToString() -ne $Version) {
            "Updating {0} version: {1} --> {2}" -f $modManifest.BaseName, $manifest.Version.ToString(), $Version | Write-Host
            Update-ModuleManifest -ModuleVersion $Version -Path $modManifest.FullName
        }
        else {
            "`r`n{0} version does not need to be updated." -f $Version | Write-Host
        }
    }
    catch {
        "Failed to update the module manifest for $($modManifest.BaseName)" | Write-Error
        exit 1
    }
}

# lets try to import the module before proceeding. If there is a missing comma or syntax error in the psd1 we will fail
$moduleManifest = Get-Item -Path (Join-Path -Path $outDir -ChildPath "SDNDiagnostics\SDNDiagnostics.psd1")
"Importing module {0}" -f $moduleManifest.FullName | Write-Host
Import-Module $moduleManifest.FullName -Global -Force

if(!$?){
    $Error | Out-String | Write-Error
}

$ErrorActionPreference = $currentErrorPref
