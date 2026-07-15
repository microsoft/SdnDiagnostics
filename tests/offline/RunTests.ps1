# Load the baseline test data needed for Pester Mock
param(
    [Parameter(Mandatory = $false)]
    [string[]]$Tag,

    [Parameter(Mandatory = $false)]
    [string]$TestFile
)

$modulePath = Get-Item -Path "$PSScriptRoot\..\..\out\build\SdnDiagnostics\SdnDiagnostics.psd1" -ErrorAction SilentlyContinue
if($null -eq $modulePath){
    "Unable to locate module. Generate a local build first" | Write-Host -ForegroundColor:Yellow
    return
}

# API resources
$sdnApiResourcesPath = "$PSScriptRoot\data\SdnApiResources"
$Global:PesterOfflineTests = @{}
$Global:PesterOfflineTests.SdnApiResources = @{}
foreach($file in Get-ChildItem -Path $sdnApiResourcesPath -Filter "*.json")
{
    $content = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
    # Handle both wrapped {value:[...]} and raw array formats
    if ($null -ne $content.value) {
        $Global:PesterOfflineTests.SdnApiResources[$file.BaseName] = $content.value
    }
    else {
        $Global:PesterOfflineTests.SdnApiResources[$file.BaseName] = $content
    }
}

$Global:PesterOfflineTests.SdnApiResourcesByRef = [System.Collections.Hashtable]::new()
foreach($resourceType in $Global:PesterOfflineTests.SdnApiResources.Keys)
{
    $resourcesOfType = $Global:PesterOfflineTests.SdnApiResources[$resourceType]
    foreach($resource in $resourcesOfType)
    {
        if($null -ne $resource.resourceRef){
            $Global:PesterOfflineTests.SdnApiResourcesByRef[$resource.resourceRef] = $resource
        }
    }
}

Import-Module -Name $modulePath.FullName -Force

# Build Pester parameters
$pesterParams = @{
    Output = 'Detailed'
}

if ($TestFile) {
    $pesterParams.Path = $TestFile
}
else {
    $pesterParams.Path = "$PSScriptRoot\*Tests.ps1"
}

if ($Tag) {
    $pesterParams.Tag = $Tag
}

Invoke-Pester @pesterParams