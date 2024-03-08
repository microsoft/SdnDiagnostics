param(
    [System.IO.FileInfo]$Manifest,
    [string]$Version
)

$currentErrorPref = $ErrorActionPreference
$ErrorActionPreference = 'Stop'

if ([String]::IsNullOrEmpty($Version)) {
    [String]$Version = $env:CUSTOM_VERSION
}

try {
    $manifestData = Import-PowerShellDataFile -Path $Manifest.FullName -Verbose
    $modParams = @{
        RootModule = $manifestData.RootModule
        Author = $manifestData.Author
        CompanyName = $manifestData.CompanyName
        Copyright = $manifestData.Copyright
        GUID = $manifestData.GUID
        Description = $manifestData.Description
        ModuleVersion = $Version
        PowershellVersion = $manifestData.PowerShellVersion
        NestedModules = $manifestData.NestedModules
        RequiredModules = $manifestData.RequiredModules
        CmdletsToExport = $manifestData.CmdletsToExport
        FunctionsToExport = $manifestData.FunctionsToExport
        VariablesToExport = $manifestData.VariablesToExport
        AliasesToExport = $manifestData.AliasesToExport
        Tags = $manifestData.PrivateData.PSData.Tags
        LicenseUri = $manifestData.PrivateData.PSData.LicenseUri
        ProjectUri = $manifestData.PrivateData.PSData.ProjectUri
    }

    Remove-Item -Path $Manifest.FullName -Force -Verbose
    New-ModuleManifest -Path $Manifest.FullName @modParams -Verbose
}
catch {
    "Failed to update the generate manifest for $($Manifest.BaseName)`n{0}" -f $_.Exception | Write-Error
    exit 1
}

$ErrorActionPreference = $currentErrorPref
