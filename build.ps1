if (Get-Module -Name 'SdnDiagnostics') {
    Remove-Module -Name 'SdnDiagnostics' -Force
}

.$PSScriptRoot\.build\clean.ps1
.$PSScriptRoot\.build\restore.ps1
$buildVersion = .$PSScriptRoot\.build\generate-Version.ps1
if ($buildVersion) {
    .$PSScriptRoot\.build\build.ps1 -Version $buildVersion
    .$PSScriptRoot\.build\package.ps1 -Version $buildVersion
}

