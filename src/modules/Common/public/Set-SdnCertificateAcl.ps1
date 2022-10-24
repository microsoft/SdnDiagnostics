function Set-SdnCertificateAcl {
    <#
        .SYNOPSIS
        Configures NT AUTHORITY/NETWORK SERVICE to have appropriate permissions to the private key of the Network Controller certificates.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Subject')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Thumbprint')]
        [ValidateScript({
            if ($_ -notlike "cert:\*") {
                throw New-Object System.FormatException("Invalid path")
            }

            return $true
        })]
        [System.String]$Path,

        [Parameter(Mandatory = $true, ParameterSetName = 'Subject')]
        [System.String]$Subject,

        [Parameter(Mandatory = $true, ParameterSetName = 'Thumbprint')]
        [System.String]$Thumbprint
    )

    try {
        switch ($PSCmdlet.ParameterSetName) {
            'Subject' {
                $certificate = Get-SdnCertificate -Path $Path -Subject $Subject
            }
            'Thumbprint' {
                $certificate = Get-SdnCertificate -Path $Path -Thumbprint $Thumbprint
            }
        }

        if ($null -eq $certificate) {
            throw New-Object System.NullReferenceException("Unable to locate the certificate based on $($PSCmdlet.ParameterSetName)")
        }
        else {
            "Located certificate with Thumbprint: {0} and Subject: {1}" -f $certificate.Thumbprint, $certificate.Subject | Trace-Output -Level:Verbose
        }

        if ($certificate.Count -ge 2) {
            throw New-Object System.Exception("Multiple certificates found matching $($PSCmdlet.ParameterSetName)")
        }

        if ($certificate.HasPrivateKey) {
            $privateKeyCertFile = Get-Item -Path "$($env:ProgramData)\Microsoft\Crypto\RSA\MachineKeys\*" | Where-Object {$_.Name -ieq $($certificate.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName)}
            $privateKeyAcl = Get-Acl -Path $privateKeyCertFile.FullName
            if ($privateKeyAcl.Access.IdentityReference -inotcontains "NT AUTHORITY\NETWORK SERVICE") {
                $networkServicePermission = "NT AUTHORITY\NETWORK SERVICE", "Read", "Allow"
                "Configuring {0} on {1}" -f ($networkServicePermission -join ', ').ToString(), $privateKeyCertFile.FullName | Trace-Output

                $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($networkServicePermission)
                [void]$privateKeyAcl.AddAccessRule($accessRule)
                $null = Set-Acl -Path $privateKeyCertFile.FullName -AclObject $privateKeyAcl
            }
            else {
                "Permissions already defined for NT AUTHORITY\NETWORK SERVICE for {0}. No ACL changes required." -f $certificate.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName | Trace-Output -Level:Verbose
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
