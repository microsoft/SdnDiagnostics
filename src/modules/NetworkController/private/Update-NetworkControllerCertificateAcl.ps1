# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Update-NetworkControllerCertificateAcl {
    <#
    .SYNOPSIS
        Update the Network Controller Certificate to grant Network Service account read access to the private key.
    .PARAMETER NcVMs
        The list of Network Controller VMs.
	.PARAMETER NcRestName
		The Network Controller REST Name in FQDN format used to find the REST Certificate to be used.
	.PARAMETER ClusterCredentialType
		X509, Windows or None. Network Controller Node Certificate ACL will be updated only when the ClusterCredentialType is X509.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String[]]
        $NcVMs,
        [Parameter(Mandatory = $true)]
        [String]
        $NcRestName,
        [Parameter(Mandatory = $false)]
        [String]
        $ClusterCredentialType = "X509",
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        foreach ($ncVm in $NcVMs) {
            Invoke-Command -ComputerName $ncVm -ScriptBlock {

                if($using:ClusterCredentialType -eq "X509")
                {
                    # Update Node Certificate only when auth type is certificate
                    $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName + "." + (get-ciminstance win32_computersystem).Domain
                    $Cert = get-childitem "Cert:\localmachine\my" | where-object { $_.Subject.ToUpper().StartsWith("CN=$NodeFQDN".ToUpper()) } | Sort-Object -Property NotBefore -Descending | Select-Object -First 1 
                    Write-Host "Set ACL of cert private key on $NodeFQDN for Node certificate: $($Cert.Thumbprint)"
                    
                    $targetCertPrivKey = $Cert.PrivateKey 
                    $privKeyCertFile = Get-Item -path "$ENV:ProgramData\Microsoft\Crypto\RSA\MachineKeys\*"  | where-object { $_.Name -eq $targetCertPrivKey.CspKeyContainerInfo.UniqueKeyContainerName } 
                    $privKeyAcl = Get-Acl $privKeyCertFile
                    $permission = "NT AUTHORITY\NETWORK SERVICE", "Read", "Allow" 
                    $accessRule = new-object System.Security.AccessControl.FileSystemAccessRule $permission 
                    $privKeyAcl.AddAccessRule($accessRule) | out-null
                    Set-Acl $privKeyCertFile.FullName $privKeyAcl | out-null
                }

                $Cert = get-childitem "Cert:\localmachine\my" | where-object { $_.Subject.ToUpper().StartsWith("CN=$($using:NcRestName)".ToUpper()) } | Sort-Object -Property NotBefore -Descending | Select-Object -First 1
                Write-Host "Set ACL of cert private key on $NodeFQDN for REST certificate: $($Cert.Thumbprint)"
                
                $targetCertPrivKey = $Cert.PrivateKey 
                $privKeyCertFile = Get-Item -path "$ENV:ProgramData\Microsoft\Crypto\RSA\MachineKeys\*"  | where-object { $_.Name -eq $targetCertPrivKey.CspKeyContainerInfo.UniqueKeyContainerName } 
                $privKeyAcl = Get-Acl $privKeyCertFile
                $permission = "NT AUTHORITY\NETWORK SERVICE", "Read", "Allow" 
                $accessRule = new-object System.Security.AccessControl.FileSystemAccessRule $permission 
                $privKeyAcl.AddAccessRule($accessRule) | out-null
                Set-Acl $privKeyCertFile.FullName $privKeyAcl | out-null
            } -Credential $Credential
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}