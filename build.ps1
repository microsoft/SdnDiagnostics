if (Get-Module -Name 'SdnDiagnostics') {
    Remove-Module -Name 'SdnDiagnostics' -Force
}

.$PSScriptRoot\.build\clean.ps1
$buildVersion = .$PSScriptRoot\.build\generate-Version.ps1
if ($buildVersion) {
    .$PSScriptRoot\.build\build.ps1 -Version $buildVersion
    .$PSScriptRoot\.build\generate-module-manifest.ps1 -Manifest (Get-Item -Path ".\out\build\SdnDiagnostics\SdnDiagnostics.psd1") -Version $buildVersion
    .$PSScriptRoot\.build\package.ps1 -Version $buildVersion
}

