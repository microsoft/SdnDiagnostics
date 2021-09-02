param(
    [Parameter(Mandatory = $true)]
    [String] $ConfigurationFile
)
$Global:PesterOnlineTests  = @{
}

$Global:PesterOnlineTests.ConfigData = [hashtable] (Invoke-Expression (Get-Content $ConfigurationFile | Out-String))

$Global:PesterOnlineTests.NcRestCredential = [System.Management.Automation.PSCredential]::Empty
#$ncAdminCredential = [System.Management.Automation.PSCredential]::Empty
if($null -ne $Global:PesterOnlineTests.ConfigData.NcRestCredentialUser){
    $ncRestSecurePassword = $Global:PesterOnlineTests.ConfigData.NcRestCredentialPassword | ConvertTo-SecureString
    $Global:PesterOnlineTests.NcRestCredential = New-Object System.Management.Automation.PsCredential($Global:PesterOnlineTests.ConfigData.NcRestCredentialUser, $ncRestSecurePassword)
}

Import-Module $Global:PesterOnlineTests.ConfigData.SdnDiagnosticsModule -Force

# Tests can be arranged in different wave if order matters
Invoke-Pester ".\wave1\*Tests.ps1" -Output Detailed
Invoke-Pester ".\waveAll\*Tests.ps1" -Output Detailed