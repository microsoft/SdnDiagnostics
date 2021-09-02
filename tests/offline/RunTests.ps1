# Load the baseline test data needed for Pester Mock

# API resources
$sdnApiResourcesPath = ".\data\SdnApiResources"
$Global:PesterOfflineTests = @{}
$Global:PesterOfflineTests.SdnApiResources = @{}
foreach($file in Get-ChildItem $sdnApiResourcesPath)
{
    $Global:PesterOfflineTests.SdnApiResources[$file.BaseName] = Get-Content $file.FullName | ConvertFrom-Json
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

Import-Module "..\..\out\build\SdnDiagnostics\SdnDiagnostics.psd1" -Force

Invoke-Pester ".\*Tests.ps1" -Output Detailed