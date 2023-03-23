function Test-HostRootStoreNonRootCert {
    <#
    .SYNOPSIS
        Validate the Cert in Host's Root CA Store to detect if any Non Root Cert exist
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricHealthObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()
    $array = @()

    try {
        "Validating Certificates under Root CA Store" | Trace-Output

        $scriptBlock = {
            $nonRootCerts = @()
            $rootCerts = Get-ChildItem Cert:LocalMachine\Root
            foreach ($rootCert in $rootCerts) {
                if ($rootCert.Subject -ne $rootCert.Issuer) {
                    $certInfo = [PSCustomObject]@{
                        Thumbprint = $rootCert.Thumbprint
                        Subject    = $rootCert.Subject
                        Issuer     = $rootCert.Issuer
                    }

                    $nonRootCerts += $certInfo
                }
            }
            return $nonRootCerts
        }

        foreach($node in $SdnEnvironmentObject.ComputerName){
            $nonRootCerts = Invoke-PSRemoteCommand -ComputerName $node -Credential $Credential -ScriptBlock $scriptBlock -PassThru
            # If any node have Non Root Certs in Trusted Root Store. Issue detected.
            if($nonRootCerts.Count -gt 0){
                $sdnHealthObject.Result = 'FAIL'

                $object = [PSCustomObject]@{
                    ComputerName = $node
                    NonRootCerts = $nonRootCerts
                }

                $array += $object
            }
        }

        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
