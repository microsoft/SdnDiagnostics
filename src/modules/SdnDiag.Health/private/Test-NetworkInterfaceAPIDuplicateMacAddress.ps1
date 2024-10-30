function Test-NetworkInterfaceAPIDuplicateMacAddress {
    <#
    .SYNOPSIS
        Validate there are no adapters within the Network Controller Network Interfaces API that are duplicate.
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate
    )

    $ncRestParams = @{
        NcUri = $SdnEnvironmentObject.NcUrl
    }
    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $ncRestParams.Add('NcRestCredential', $NcRestCredential)
        }
    }

    $sdnHealthObject = [SdnHealth]::new()
    $array = @()

    try {
        "Validate no duplicate MAC addresses for network interfaces in Network Controller" | Trace-Output

        $networkInterfaces = Get-SdnResource @ncRestParams -Resource:NetworkInterfaces
        if($null -eq $networkInterfaces){
            # if there are no network interfaces, then there is nothing to validate
            # pass back the health object to the caller
            return $sdnHealthObject
        }

        $duplicateObjects = $networkInterfaces.properties | Group-Object -Property privateMacAddress | Where-Object {$_.Count -ge 2}
        if($duplicateObjects){
            $sdnHealthObject.Result = 'FAIL'

            # since there can be multiple grouped objects, we need to enumerate each duplicate group
            foreach($obj in $duplicateObjects){
                $sdnHealthObject.Remediation += "Remove the duplicate MAC addresses for $($obj.Name) within Network Controller Network Interfaces"

                $duplicateInterfaces = $networkInterfaces | Where-Object {$_.properties.privateMacAddress -eq $obj.Name}
                $array += $duplicateInterfaces

                "Located {0} virtual machines associated with MAC address {1}:`r`n`n{2}`r`n" -f $obj.Count, $obj.Name, `
                    ($duplicateInterfaces `
                    | Select-Object @{n="ResourceRef";e={"`t$($_.resourceRef)"}} `
                    | Select-Object -ExpandProperty ResourceRef `
                    | Out-String `
                ) | Trace-Output -Level:Error
            }
        }

        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
