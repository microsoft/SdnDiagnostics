function Get-OvsdbUcastMacRemoteTable {
    <#
    .SYNOPSIS
        Returns a list of mac addresses defined within the Ucast_Macs_Remote table of the OVSDB database.
    .EXAMPLE
        PS> Get-OvsdbUcastMacRemoteTable
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
            $result = [OvsdbUcastMacRemote]@{
                UUID            = $obj[1][1]
                MacAddress      = $obj[0]
                CustomerAddress = $obj[2]
                Locator         = $obj[3][1]
                LogicalSwitch   = $obj[4][1]
                MappingType     = $obj[5]
            }

            [void]$arrayList.Add($result)
        }

        return $arrayList
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
