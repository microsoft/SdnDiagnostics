# Load the baseline test data needed for Pester Mock

$modulePath = Get-Item -Path "$PSScriptRoot\..\..\out\build\SdnDiagnostics\SdnDiagnostics.psd1" -ErrorAction SilentlyContinue
if($null -eq $modulePath){
    "Unable to locate module. Generate a local build first" | Write-Host -ForegroundColor:Yellow
    return
}

# API resources
$sdnApiResourcesPath = "$PSScriptRoot\data\SdnApiResources"
$Global:PesterOfflineTests = @{}
$Global:PesterOfflineTests.SdnApiResources = @{}
foreach($file in Get-ChildItem -Path $sdnApiResourcesPath)
{
    $Global:PesterOfflineTests.SdnApiResources[$file.BaseName] = Get-Content -Path $file.FullName | ConvertFrom-Json
}

$Global:PesterOfflineTests.SdnApiResourcesByRef = [System.Collections.Hashtable]::new()
foreach($resourceType in $Global:PesterOfflineTests.SdnApiResources.Keys)
{
    $resourcesOfType = $Global:PesterOfflineTests.SdnApiResources[$resourceType]
    foreach($resource in $resourcesOfType)
    {
        if($null -ne $resource.resourceRef){
            $Global:PesterOfflineTests.SdnApiResourcesByRef.Add($resource.resourceRef, $resource)
        }
    }
}

Import-Module -Name $modulePath.FullName -Force

Invoke-Pester "$PSScriptRoot\*Tests.ps1" -Output Detailed