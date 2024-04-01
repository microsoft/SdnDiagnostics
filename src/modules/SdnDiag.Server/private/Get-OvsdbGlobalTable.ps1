function Get-OvsdbGlobalTable {
    <#
    .SYNOPSIS
        Returns the global table configuration from OVSDB database.
    .EXAMPLE
        PS> Get-OvsdbGlobalTable
    #>

    [CmdletBinding()]
    param()

    $arrayList = [System.Collections.ArrayList]::new()

    $ovsdbResults = Get-OvsdbDatabase -Table ms_vtep
    $globalTable = $ovsdbResults | Where-Object { $_.caption -eq 'Global table' }

    if ($null -eq $globalTable) {
        return $null
    }

    # enumerate the json results and add to psobject
    foreach ($obj in $globalTable.data) {
        $result = [OvsdbGlobalTable]@{
            uuid     = $obj[0][1]
            CurrentConfig  = $obj[1]
            NextConfig = $obj[4]
            Switches = $obj[6][1]
        }

        # add the psobject to array
        [void]$arrayList.Add($result)
    }

    return $arrayList
}
