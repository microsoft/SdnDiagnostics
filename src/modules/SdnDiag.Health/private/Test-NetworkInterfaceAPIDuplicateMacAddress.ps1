function Test-NetworkInterfaceAPIDuplicateMacAddress {
    <#
    .SYNOPSIS
        Validate there are no adapters within the Network Controller Network Interfaces API that are duplicate.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricHealthObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()
    $array = @()

    try {
        "Validate no duplicate MAC addresses for network interfaces in Network Controller" | Trace-Output

        $networkInterfaces = Get-SdnResource -NcUri $SdnEnvironmentObject.NcUrl.AbsoluteUri -Resource:NetworkInterfaces -Credential $NcRestCredential
        if($null -eq $networkInterfaces){
            throw New-Object System.NullReferenceException("No network interfaces returned from Network Controller")
        }

        $duplicateObjects = $networkInterfaces.properties | Group-Object -Property privateMacAddress | Where-Object {$_.Count -ge 2}
        if($duplicateObjects){
            $sdnHealthObject.Result = 'FAIL'

            # since there can be multiple grouped objects, we need to enumerate each duplicate group
            foreach($obj in $duplicateObjects){
                $duplicateInterfaces = $networkInterfaces | Where-Object {$_.properties.privateMacAddress -eq $obj.Name}
                $array += $duplicateInterfaces

                "Located {0} virtual machines associated with MAC address {1}:`r`n`n{2}`r`n" -f $obj.Count, $obj.Name, `
                    ($duplicateInterfaces `
                    | Select-Object @{n="ResourceRef";e={"`t$($_.resourceRef)"}} `
                    | Select-Object -ExpandProperty ResourceRef `
                    | Out-String `
                ) | Trace-Output -Level:Exception
            }
        }

        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
