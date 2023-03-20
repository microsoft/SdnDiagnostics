function Test-VMNetAdapterDuplicateMacAddress {
    <#
    .SYNOPSIS
        Validate there are no adapters within hyper-v dataplane that may have duplicate MAC addresses.
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
        "Validate no duplicate MAC addresses for network adapters within Hyper-V" | Trace-Output

        $vmNetAdapters = Get-SdnVMNetworkAdapter -ComputerName $SdnEnvironmentObject.ComputerName -AsJob -PassThru -Timeout 900 -Credential $Credential
        $duplicateObjects = $vmNetAdapters | Group-Object -Property MacAddress | Where-Object {$_.Count -ge 2}
        if($duplicateObjects){
            $array += $duplicateObjects
            $sdnHealthObject.Result = 'FAIL'

            # since there can be multiple grouped objects, we need to enumerate each duplicate group
            foreach($obj in $duplicateObjects){
                "Located {0} virtual machines associated with MAC address {1}:`r`n`n{2}`r`n" -f $obj.Count, $obj.Name, `
                    ($obj.Group `
                    | Select-Object @{n="VMName";e={"`t$($_.VMName)"}} `
                    | Select-Object -ExpandProperty VMName `
                    | Out-String `
                ) | Trace-Output -Level:Warning
            }
        }

        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
