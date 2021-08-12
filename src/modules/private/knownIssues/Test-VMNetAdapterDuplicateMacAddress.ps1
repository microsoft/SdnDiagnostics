# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-VMNetAdapterDuplicateMacAddress {
    <#
    .SYNOPSIS
        Validate there are no adapters within hyper-v dataplane that may have duplicate MAC addresses
    #>
    
    try {
        "Validate no duplicate MAC addresses for network adapters within Hyper-V" | Trace-Output

        [Uri]$ncUri = $Global:SdnDiagnostics.EnvironmentInfo.NcUrl
        
        $credential = [System.Management.Automation.PSCredential]::Empty
        if($Global:SdnDiagnostics.Credential){
            $credential = $Global:SdnDiagnostics.Credential
        }
    
        $ncRestCredential = [System.Management.Automation.PSCredential]::Empty
        if($Global:SdnDiagnostics.NcRestCredential){
            $ncRestCredential = $Global:SdnDiagnostics.NcRestCredential
        }

        $issueDetected = $false
        $arrayList = [System.Collections.ArrayList]::new()

        $servers = (Get-SdnServer -NcUri $ncUri.AbsoluteUri -ManagementAddressOnly -Credential $ncRestCredential)
        $vmNetAdapters = Get-SdnVMNetAdapter -ComputerName $servers -AsJob -PassThru -Timeout 900 -Credential $credential
        $duplicateObjects = $vmNetAdapters | Group-Object -Property MacAddress | Where-Object {$_.Count -ge 2}
        if($duplicateObjects){
            [void]$arrayList.Add($duplicateObjects)
            $issueDetected = $true

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
    
        return [PSCustomObject]@{
            Result = $issueDetected
            Properties = $arrayList
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}