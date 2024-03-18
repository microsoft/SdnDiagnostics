param (
    [System.IO.DirectoryInfo]$OutputDirectory = "$PSScriptRoot\..\out\build"
)

$currentErrorPref = $ErrorActionPreference
$ErrorActionPreference = 'Stop'

if (-NOT (Test-Path -Path $OutputDirectory.FullName -PathType Container)) {
    $null = New-Item -ItemType:Directory -Path $OutputDirectory.FullName -Force
}

$folders = Get-ChildItem -Path $PSScriptRoot\..\src -Directory
foreach ($folder in $folders) {

    $outDirFolder = New-Item -Path (Join-Path -Path $OutputDirectory.FullName -ChildPath "SdnDiagnostics\$($folder.BaseName)") -ItemType Directory -Force
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

                    Start-Sleep -Milliseconds 50
                }
            }

            Copy-Item -Path "$($folder.FullName)\*.psm1" -Destination "$($OutputDirectory.FullName)\SdnDiagnostics\modules\"
        }
        default {
            Copy-Item -Path "$($folder.FullName)\*" -Destination $outDirFolder -Recurse -Force
        }
    }
}

# copy the root files under src that are prefixed with SdnDiagnostics
"Copying \src\SdnDiagnostics.* files to $($OutputDirectory.FullName)\SdnDiagnostics" | Write-Host
Copy-Item -Path "$PSScriptRoot\..\src\*" -Include "SdnDiagnostics.*" -Destination "$($OutputDirectory.FullName)\SdnDiagnostics\" -Force

"Successfully generated the directory module structure under $($OutputDirectory.FullName)" | Write-Host
$ErrorActionPreference = $currentErrorPref
