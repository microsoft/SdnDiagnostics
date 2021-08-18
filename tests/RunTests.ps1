param(
    [Parameter(Mandatory = $true)]
    [String] $ConfigurationFile
)
$Global:PesterGlobal  = @{
}

$Global:PesterGlobal.ConfigData = [hashtable] (Invoke-Expression (Get-Content $ConfigurationFile | out-string))

$Global:PesterGlobal.NcRestCredential = [System.Management.Automation.PSCredential]::Empty
#$ncAdminCredential = [System.Management.Automation.PSCredential]::Empty
if($null -ne $configdata.NcRestCredentialUser){
    $ncRestSecurePassword = $configdata.NcRestCredentialPassword | ConvertTo-SecureString -AsPlainText -Force
    $Global:PesterGlobal.NcRestCredential = New-Object System.Management.Automation.PsCredential($configdata.NcRestCredentialUser, $ncRestSecurePassword)
}

Import-Module $Global:PesterGlobal.ConfigData.SdnDiagnosticsModule

# Tests can be arranged in different wave if order matters
Invoke-Pester ".\wave1\*Tests.ps1" -Output Detailed
Invoke-Pester ".\waveAll\*Tests.ps1" -Output Detailed