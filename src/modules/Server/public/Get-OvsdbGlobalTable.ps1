function Get-OvsdbGlobalTable {
    <#
    .SYNOPSIS
        Returns the global table configuration from OVSDB
    #>

    try {      
        $arrayList = [System.Collections.ArrayList]::new()

        $ovsdbResults = Get-OvsdbDatabase -Table ms_vtep
        $globalTable = $ovsdbResults | Where-Object { $_.caption -eq 'Global table' }

        # enumerate the json results and add to psobject
        foreach ($obj in $globalTable.data) {
            $result = New-Object PSObject -Property @{
                uuid     = $obj[0][1]
                cur_cfg  = $obj[1]
                next_cfg = $obj[4]
                switches = $obj[6][1]
            }
            # add the psobject to array
            [void]$arrayList.Add($result)
        }

        return $arrayList
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
