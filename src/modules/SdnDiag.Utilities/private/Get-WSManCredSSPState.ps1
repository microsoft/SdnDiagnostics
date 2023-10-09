function Get-WSManCredSSPState {
    if (Test-Path -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation') {
        if (Test-Path -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials') {
            $allowFreshCredentials = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -Name 'AllowFreshCredentials' | Select-Object -ExpandProperty 'AllowFreshCredentials'
            if ($allowFreshCredentials -eq 1) {
                return $true
            }
        }
    }

    return $false
}
