param(
    [Parameter(Mandatory = $true)]
    [String] $ConfigurationFile
)
$Global:PesterGlobal  = @{
}

$Global:PesterGlobal.ConfigData = [hashtable] (Invoke-Expression (Get-Content $ConfigurationFile | out-string))

$Global:PesterGlobal.NcRestCredential = [System.Management.Automation.PSCredential]::Empty
#$ncAdminCredential = [System.Management.Automation.PSCredential]::Empty
if($null -ne $Global:PesterGlobal.ConfigData.NcRestCredentialUser){
    $ncRestSecurePassword = $Global:PesterGlobal.ConfigData.NcRestCredentialPassword | ConvertTo-SecureString
    $Global:PesterGlobal.NcRestCredential = New-Object System.Management.Automation.PsCredential($Global:PesterGlobal.ConfigData.NcRestCredentialUser, $ncRestSecurePassword)
}

Import-Module $Global:PesterGlobal.ConfigData.SdnDiagnosticsModule -Force

# Tests can be arranged in different wave if order matters
Invoke-Pester ".\wave1\*Tests.ps1" -Output Detailed
Invoke-Pester ".\waveAll\*Tests.ps1" -Output Detailed