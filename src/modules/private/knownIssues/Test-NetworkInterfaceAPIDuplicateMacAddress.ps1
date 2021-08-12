# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-NetworkInterfaceAPIDuplicateMacAddress {
    <#
    .SYNOPSIS
        Validate there are no adapters within hyper-v dataplane that may have duplicate MAC addresses
    #>
    
    try {
        "Checking for orphaned network interfaces in Network Controller" | Trace-Output

        [Uri]$ncUri = $Global:SdnDiagnostics.EnvironmentInfo.NcUrl
        
        $ncRestCredential = [System.Management.Automation.PSCredential]::Empty
        if($Global:SdnDiagnostics.NcRestCredential){
            $ncRestCredential = $Global:SdnDiagnostics.NcRestCredential
        }

        $issueDetected = $false
        $arrayList = [System.Collections.ArrayList]::new()

        $networkInterfaces = Get-SdnResource -NcUri $ncUri.AbsoluteUri -ResourceType:NetworkInterfaces -Credential $ncRestCredential
        $duplicateObjects = $networkInterfaces | Group-Object -Property MacAddress | Where-Object {$_.Count -ge 2}

        if($duplicateObjects){
            [void]$arrayList.Add($duplicateObjects)
            $issueDetected = $true

            # since there can be multiple grouped objects, we need to enumerate each duplicate group
            foreach($obj in $duplicateObjects){
                "Located {0} virtual machines associated with MAC address {1}:`r`n`n{2}`r`n" -f $obj.Count, $obj.Name, `
                    ($obj.Group `
                    | Select-Object @{n="ResourceId";e={"`t$($_.resourceId)"}} `
                    | Select-Object -ExpandProperty ResourceId `
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