function Get-SdnCertificate {
    <#
        .SYNOPSIS
            Returns a list of the certificates within the given certificate store.
        .PARAMETER Path
            Defines the path within the certificate store. Path is expected to start with cert:\.
        .EXAMPLE
            PS> Get-SdnCertificate -Path "Cert:\LocalMachine\My"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if ($_ -notlike "cert:\*") {
                throw New-Object System.FormatException("Invalid path")
            }

            return $true
        })]
        [System.String]$Path,

        [Parameter(Mandatory = $false, ParameterSetName = 'SubjectName')]
        [System.String]$SubjectName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Thumbprint')]
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
                else {
                    $result | Add-Member -MemberType NoteProperty -Name $property.Name -Value $property.value
                }
            }

            $certificates += $result
        }

        if ($SubjectName) {
            return ($certificates | Where-Object {$_.SubjectName -ieq $SubjectName})
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
