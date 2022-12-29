function Get-SdnCertificate {
    <#
        .SYNOPSIS
            Returns a list of the certificates within the given certificate store.
        .PARAMETER Path
            Defines the path within the certificate store. Path is expected to start with cert:\.
        .EXAMPLE
            PS> Get-SdnCertificate -Path "Cert:\LocalMachine\My"
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Subject')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Thumbprint')]
        [ValidateScript({
            if ($_ -notlike "cert:\*") {
                throw New-Object System.FormatException("Invalid path")
            }

            return $true
        })]
        [System.String]$Path,

        [Parameter(Mandatory = $false, ParameterSetName = 'Subject')]
        [ValidateNotNullorEmpty()]
        [System.String]$Subject,

        [Parameter(Mandatory = $false, ParameterSetName = 'Thumbprint')]
        [ValidateNotNullorEmpty()]
        [System.String]$Thumbprint
    )

    try {
        $certificateList = Get-ChildItem -Path $Path -Recurse | Where-Object {$_.PSISContainer -eq $false} -ErrorAction Stop

        switch ($PSCmdlet.ParameterSetName) {
            'Subject' {
                $filteredCert = $certificateList | Where-Object {$_.Subject -ieq $Subject}
            }
            'Thumbprint' {
                $filteredCert = $certificateList | Where-Object {$_.Thumbprint -ieq $Thumbprint}
            }
            default {
                return $certificateList
            }
        }

        if ($null -eq $filteredCert) {
            "Unable to locate certificate using {0}" -f $PSCmdlet.ParameterSetName | Trace-Output -Level:Warning
            return $null
        }

        if ($filteredCert.NotAfter -le (Get-Date)) {
            "Certificate [Thumbprint: {0} | Subject: {1}] is currently expired" -f $filteredCert.Thumbprint, $filteredCert.Subject | Trace-Output -Level:Exception
        }

        return $filteredCert
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
