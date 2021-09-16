# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-OvsdbUcastMacRemoteTable {
    <#
    .SYNOPSIS
        Returns a list of mac addresses defined within the Ucast_Macs_Remote table of the OVSDB database.
    #>

    try {
        $arrayList = [System.Collections.ArrayList]::new()

        $ovsdbResults = Get-OvsdbDatabase -Table ms_vtep
        $ucastMacsRemoteTable = $ovsdbResults | Where-Object { $_.caption -eq 'Ucast_Macs_Remote table' }

        if ($null -eq $ucastMacsRemoteTable) {
            return $null
        }
        
        # enumerate the json objects and create psobject for each port
        foreach ($obj in $ucastMacsRemoteTable.data) {
            $result = New-Object PSObject -Property @{
                uuid           = $obj[1][1]
                mac            = $obj[0]
                ipaddr         = $obj[2]
                locator        = $obj[3][1]
                logical_switch = $obj[4][1]
                mapping_type   = $obj[5]
            }

            [void]$arrayList.Add($result)
        }

        return $arrayList
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
