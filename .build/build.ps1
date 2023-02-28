param (
    [String]$Version
)

$currentErrorPref = $ErrorActionPreference
$ErrorActionPreference = 'Stop'


$outDir = "$PSScriptRoot\..\out\build"
if (-NOT (Test-Path -Path $outDir -PathType Container)) {
    $null = New-Item -ItemType:Directory -Path $outDir -Force
}

$folders = Get-ChildItem -Path $PSScriptRoot\..\src -Directory
foreach ($folder in $folders) {

    $outDirFolder = New-Item -Path (Join-Path -Path $outDir -ChildPath "SdnDiagnostics\$($folder.BaseName)") -ItemType Directory -Force
    switch ($folder.Name) {
        'enum' {
            $powershellFile = New-Item -Path (Join-Path -Path $outDirFolder.FullName -ChildPath "SdnDiag.Enum.ps1")
            foreach ($file in (Get-ChildItem -Path $folder.FullName -Recurse -Include *.ps1)) {
                $content = Get-Content -Path $file.FullName -Raw
                $powershellFile | Add-Content -Value $content
            }
        }

        'classes' {
            $powershellFile = New-Item -Path (Join-Path -Path $outDirFolder.FullName -ChildPath "SdnDiag.Classes.ps1")
            foreach ($file in (Get-ChildItem -Path $folder.FullName -Recurse -Include *.ps1)) {
                $content = Get-Content -Path $file.FullName -Raw
                $powershellFile | Add-Content -Value $content
            }
        }

        'modules' {
            foreach ($moduleDir in (Get-ChildItem -Path "$PSScriptRoot\..\src\modules" -Directory)) {
                $powershellFile = New-Item -Path (Join-Path -Path $outDirFolder.FullName -ChildPath "$($moduleDir.BaseName).ps1")
                foreach ($file in (Get-ChildItem -Path $moduleDir.FullName -Recurse -Include *.ps1)) {
                    $content = Get-Content -Path $file.FullName -Raw
                    $powershellFile | Add-Content -Value $content
                }
            }

            Copy-Item -Path "$($folder.FullName)\*.ps1" -Destination "$outDir\SdnDiagnostics\modules\"
        }
        default {
            Copy-Item -Path "$($folder.FullName)\*" -Destination $outDirFolder -Recurse -Force
        }
    }
}

Copy-Item -Path "$PSScriptRoot\..\src\SdnDiagnostics.*" -Destination "$outDir\SdnDiagnostics\" -Force
Copy-Item -Path "$PSScriptRoot\..\src\SdnDiagnostics.*" -Destination "$outDir\SdnDiagnostics\" -Force

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
