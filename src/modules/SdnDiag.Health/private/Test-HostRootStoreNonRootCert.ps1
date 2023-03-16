function Test-HostRootStoreNonRootCert {
    <#
    .SYNOPSIS
        Validate the Cert in Host's Root CA Store to detect if any Non Root Cert exist
    .DESCRIPTION
        Validate the Cert in Host's Root CA Store to detect if any Non Root Cert exist. Non Root Cert is the cert that Issuer not equal to Subject
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    .EXAMPLE
        PS> Test-HostRootStoreNonRootCert
    .EXAMPLE
        PS> Test-HostRootStoreNonRootCert -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Test-HostRootStoreNonRootCert -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()
    $sdnHealthObject.Result = 'PASS'
    $arrayList = [System.Collections.ArrayList]::new()

    try {
        "Validating Certificates under Root CA Store" | Trace-Output

        $scriptBlock = {
            $nonRootCerts = [System.Collections.ArrayList]::new()
            $rootCerts = Get-ChildItem Cert:LocalMachine\Root
            foreach ($rootCert in $rootCerts) {
                if ($rootCert.Subject -ne $rootCert.Issuer) {
                    $certInfo = [PSCustomObject]@{
                        Thumbprint = $rootCert.Thumbprint
                        Subject    = $rootCert.Subject
                        Issuer     = $rootCert.Issuer
                    }
                    [void]$nonRootCerts.Add($certInfo)
                }
            }
            return $nonRootCerts
        }

        foreach($node in $ComputerName){
            $nonRootCerts = Invoke-PSRemoteCommand -ComputerName $node -Credential $Credential -ScriptBlock $scriptBlock -PassThru
            # If any node have Non Root Certs in Trusted Root Store. Issue detected.
            if($nonRootCerts.Count -gt 0){
                $sdnHealthObject.Result = 'FAIL'

                $object = [PSCustomObject]@{
                    ComputerName = $node
                    NonRootCerts = $nonRootCerts
                }

                [void]$arrayList.Add($object)
            }
        }

        $sdnHealthObject.Properties = $arrayList
        return $sdnHealthObject
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
