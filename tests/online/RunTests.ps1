param(
    [Parameter(Mandatory = $true)]
    [String] $ConfigurationFile
)
$Global:PesterOnlineTests  = @{
}

$Global:PesterOnlineTests.ConfigData = [hashtable] (Invoke-Expression (Get-Content -Path $ConfigurationFile | Out-String))

$Global:PesterOnlineTests.NcRestCredential = [System.Management.Automation.PSCredential]::Empty
#$ncAdminCredential = [System.Management.Automation.PSCredential]::Empty
if($null -ne $Global:PesterOnlineTests.ConfigData.NcRestCredentialUser){
    $ncRestSecurePassword = $Global:PesterOnlineTests.ConfigData.NcRestCredentialPassword | ConvertTo-SecureString
    $Global:PesterOnlineTests.NcRestCredential = New-Object System.Management.Automation.PsCredential($Global:PesterOnlineTests.ConfigData.NcRestCredentialUser, $ncRestSecurePassword)
}

if($null -eq $Global:PesterOnlineTests.ConfigData.SdnDiagnosticsModule)
{
    $modulePathFromBuild = "$PSScriptRoot\..\..\out\build\SdnDiagnostics\SdnDiagnostics.psd1"
    "Importing module from {0}" -f $modulePathFromBuild | Write-Output
    Import-Module $modulePathFromBuild
}else {
    Import-Module $Global:PesterOnlineTests.ConfigData.SdnDiagnosticsModule -Force
}

# Tests can be arranged in different wave if order matters
$testFailed = 0
$testResult = Invoke-Pester "$PSScriptRoot\wave1\*Tests.ps1" -Output Detailed -PassThru
if($testResult.Result -ne "Passed")
{
    $testFailed = 1
}
$testResult = Invoke-Pester "$PSScriptRoot\waveAll\*Tests.ps1" -Output Detailed -PassThru
if($testResult.Result -ne "Passed")
{
    $testFailed = 1
}

# Exit code 0 indicate success
return $testFailed