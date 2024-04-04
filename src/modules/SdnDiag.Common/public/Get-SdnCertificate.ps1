
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
        [System.String]$Thumbprint,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Subject')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Thumbprint')]
        [switch]$NetworkControllerOid
    )

    [string]$ObjectIdentifier = @('1.3.6.1.4.1.311.95.1.1.1') # this is a custom OID used for Network Controller
    $array = @()

    try {
        $certificateList = Get-ChildItem -Path $Path | Where-Object {$_.PSISContainer -eq $false} -ErrorAction Ignore
        if ($NetworkControllerOid) {
            $certificateList | ForEach-Object {
                if ($ObjectIdentifier -iin $_.EnhancedKeyUsageList.ObjectId) {
                    $array += $_
                }
            }
        }
        else {
            $array = $certificateList
        }

        switch ($PSCmdlet.ParameterSetName) {
            'Subject' {
                $filteredCert = $array | Where-Object {$_.Subject -ieq $Subject}
            }
            'Thumbprint' {
                $filteredCert = $array | Where-Object {$_.Thumbprint -ieq $Thumbprint}
            }
            default {
                return $array
            }
        }

        if ($null -eq $filteredCert) {
            return $null
        }

        $filteredCert | ForEach-Object {
            if ($_.NotAfter -le (Get-Date)) {
                "Certificate [Thumbprint: {0} | Subject: {1}] is currently expired" -f $_.Thumbprint, $_.Subject | Trace-Output -Level:Warning
            }
        }

        return $filteredCert
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
