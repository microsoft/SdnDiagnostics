param (
    [System.IO.DirectoryInfo]$OutputDirectory = "$PSScriptRoot\..\out\build"
)

$currentErrorPref = $ErrorActionPreference
$ErrorActionPreference = 'Stop'

if (-NOT (Test-Path -Path $OutputDirectory.FullName -PathType Container)) {
    $null = New-Item -ItemType:Directory -Path $OutputDirectory.FullName -Force
}

$outDirFolder = New-Item -Path (Join-Path -Path $OutputDirectory.FullName -ChildPath "SdnDiagnostics\") -ItemType Directory -Force

# copy the root files under src that are prefixed with SdnDiagnostics
Copy-Item -Path "$PSScriptRoot\..\src\*" -Destination $outDirFolder.FullName -Recurse

"Successfully generated the directory module structure under $($OutputDirectory.FullName)" | Write-Host
$ErrorActionPreference = $currentErrorPref
