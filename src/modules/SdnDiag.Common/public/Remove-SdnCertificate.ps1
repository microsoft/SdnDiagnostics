function Remove-SdnCertificate {
    <#
        .SYNOPSIS
            Removes a certificate from the certificate store that contains a custom Network Controller OID.
        .PARAMETER Path
            Defines the path within the certificate store. Path is expected to start with cert:\.
        .PARAMETER Thumbprint
            Specifies the thumbprint of the certificate to remove.
        .PARAMETER Subject
            Specifies the subject of the certificate to remove.
        .EXAMPLE
            PS> Remove-SdnCertificate -Path "Cert:\LocalMachine\My" -Thumbprint "1234567890ABCDEF1234567890ABCDEF12345678"
        .EXAMPLE
            PS> Remove-SdnCertificate -Path "Cert:\LocalMachine\My" -Subject "rest.sdn.contoso"
    #>

    [CmdletBinding(DefaultParameterSetName = 'Thumbprint', SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Thumbprint')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Subject')]
        [ValidateScript({
            if ($_ -notlike "cert:\*") {
                throw New-Object System.FormatException("Invalid path")
            }

            return $true
        })]
        [System.String]$Path,

        [Parameter(Mandatory = $true, ParameterSetName = 'Thumbprint')]
        [ValidateNotNullorEmpty()]
        [System.String]$Thumbprint,

        [Parameter(Mandatory = $true, ParameterSetName = 'Subject')]
        [ValidateNotNullorEmpty()]
        [System.String]$Subject
    )

    $params = @{
        Path = $Path
        NetworkControllerOid = $true
    }
    switch ($PSCmdlet.ParameterSetName) {
        'Thumbprint' {
            $params.Add('Thumbprint', $Thumbprint)
        }
        'Subject' {
            $params.Add('Subject', $Subject)
        }
    }

    try {
        $cert = Get-SdnCertificate @params
        if ($cert) {
            $cert | ForEach-Object {
                $message = "Certificate [Subject: $($_.Subject), Thumbprint: $($_.Thumbprint)]"
                if ($PSCmdlet.ShouldProcess($message)) {
                    "Removing certificate [Subject: $($_.Subject), Thumbprint: $($_.Thumbprint)] from $Path" | Trace-Output -Level:Verbose
                    $_ | Remove-Item
                }
            }
        }
        else {
            "No certificate found with with the specified $($PSCmdlet.ParameterSetName)" | Trace-Output -Level:Warning
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
