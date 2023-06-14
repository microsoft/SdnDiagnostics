param (
    [String]$Version = $env:SdnDiagCustomBuildNumber
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
        'modules' {
            foreach ($moduleDir in (Get-ChildItem -Path "$PSScriptRoot\..\src\modules" -Directory)) {
                # create the output module directory
                $outModuleDirPath = Join-Path -Path $outDirFolder.FullName -ChildPath "$($moduleDir.BaseName)"
                if (-NOT (Test-Path -Path $outModuleDirPath -PathType Container)) {
                    $null = New-Item -Path $outModuleDirPath -ItemType Directory -Force
                }

                # copy the current psm1 and psd1 files we have declared under src
                Copy-Item -Path "$($moduleDir.FullName)\*" -Include '*.psd1','*.psm1' -Destination "$outModuleDirPath\"

                # locate the psm1 file within the output module directory so that we can add all the private and public ps1 functions
                # under source to the single psm1 file
                $powershellFile = Get-Item -Path (Join-Path -Path $outModuleDirPath -ChildPath "$($moduleDir.BaseName).psm1")
                "`nUpdating module: {0}" -f $powershellFile.BaseName | Write-Host
                foreach ($file in (Get-ChildItem -Path $moduleDir.FullName -Recurse -Include '*.ps1')) {
                    "`tProcessing: {0}" -f $File.FullName | Write-Host
                    $content = Get-Content -Path $file.FullName -Raw
                    $powershellFile | Add-Content -Value $content

                    Start-Sleep -Milliseconds 200
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
        "Failed to update the module manifest for $($modManifest.BaseName)`n{0}" -f $_.Exception | Write-Error
        exit 1
    }
}

$ErrorActionPreference = $currentErrorPref
