if (Get-Module -Name 'SdnDiagnostics') {
    Remove-Module -Name 'SdnDiagnostics' -Force
}

nuget help
nuget sources

.$PSScriptRoot\.build\clean.ps1
.$PSScriptRoot\.build\restore.ps1
$buildVersion = .$PSScriptRoot\.build\generate-Version.ps1
if ($buildVersion) {
    .$PSScriptRoot\.build\build.ps1 -Version $buildVersion
    .$PSScriptRoot\.build\package.ps1 -Version $buildVersion
}

# copy the contents from .packages to the out\build folder
foreach ($item in (Get-ChildItem -Path $PSScriptRoot\.packages -Directory)) {
    $restorePath = Get-Item -Path $PSScriptRoot\out\build\SdnDiagnostics
    "Copying {0} to {1}" -f $item.BaseName, $restorePath.FullName | Write-Host
    Copy-Item -Path $item.FullName -Destination (Join-Path -Path $restorePath -ChildPath "packages\$($item.BaseName)") -Recurse -Exclude *.nupkg
}
