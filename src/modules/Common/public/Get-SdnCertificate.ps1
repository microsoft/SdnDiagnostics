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
        [ValidateScript({
            if ($_ -notlike "cert:\*") {
                throw New-Object System.FormatException("Invalid path")
            }

            return $true
        })]
        [System.String]$Path,

        [Parameter(Mandatory = $false, ParameterSetName = 'Subject')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [ValidateNotNullorEmpty()]
        [System.String]$Subject,

        [Parameter(Mandatory = $false, ParameterSetName = 'Thumbprint')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [ValidateNotNullorEmpty()]
        [System.String]$Thumbprint
    )

    try {
        $certificates = @()
        $certificateList = Get-ChildItem -Path $Path -Recurse | Where-Object {$_.PSISContainer -eq $false} -ErrorAction Stop
        foreach ($cert in $certificateList) {
            $result = New-Object PSObject
            foreach ($property in $cert.PSObject.Properties) {
                if ($property.Name -ieq 'PrivateKey') {
                    $acl = Get-Acl -Path ("$ENV:ProgramData\Microsoft\Crypto\RSA\MachineKeys\" + $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName)
                    $result | Add-Member -MemberType NoteProperty -Name "AccesstoString" -Value $acl.AccessToString
                    $result | Add-Member -MemberType NoteProperty -Name "Sddl" -Value $acl.Sddl
                }

                $result | Add-Member -MemberType NoteProperty -Name $property.Name -Value $property.value
            }

            $certificates += $result
        }

        if ($Subject) {
            return ($certificates | Where-Object {$_.Subject -ieq $Subject})
        }

        if ($Thumbprint) {
            return ($certificates | Where-Object {$_.Thumbprint -ieq $Thumbprint})
        }

        return $certificates
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
