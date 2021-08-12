# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-VfpDuplicatePort {
    <#
    .SYNOPSIS
        Validate there are no ports within VFP layer that may have duplicate MAC addresses
    #>

    try {
        [Uri]$NcUri = $Global:SdnDiagnostics.EnvironmentInfo.NcUrl

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

        $servers = Get-SdnServer -NcUri $NcUri.AbsoluteUri -ManagementAddressOnly -Credential $ncRestCredential
        $vfpPorts = Get-SdnVfpVmSwitchPort -ComputerName $servers -Credential $credential -AsJob -PassThru
        $duplicateObjects = $vfpPorts | Where-Object {$_.MACaddress -ne '00-00-00-00-00-00' -and $null -ne $_.MacAddress} | Group-Object -Property MacAddress | Where-Object {$_.Count -ge 2}

        if($duplicateObjects){
            [void]$arrayList.Add($duplicateObjects)

            # since there can be multiple grouped objects, we need to enumerate each duplicate group
            foreach($obj in $duplicateObjects){
                "Located {0} VFP ports associated with {1}:`r`n`n{2}`r`n" -f $obj.Count, $obj.Name, `
                    ($obj.Group `
                    | Select-Object @{n="Portname";e={"`t$($_.Portname)"}} `
                    | Select-Object -ExpandProperty Portname `
                    | Out-String `
                ) | Trace-Output -Level:Error
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
