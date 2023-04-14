function Get-OvsdbRouterTable {
    <#
    .SYNOPSIS
        Returns the logical router table configuration from OVSDB database.
    .EXAMPLE
        PS> Get-OvsdbRouterTable
    #>

    try {
        $arrayList = [System.Collections.ArrayList]::new()

        $ovsdbResults = Get-OvsdbDatabase -Table ms_vtep
        $routerTable = $ovsdbResults | Where-Object { $_.caption -eq 'Logical_Router table' }

        if ($null -eq $routerTable) {
            return $null
        }

        # enumerate the json results and add to psobject
        foreach ($obj in $routerTable.data) {
            $staticroute = ""
            if($obj[5][1].count -gt 0){
                foreach($route in $obj[5][1]){
                    if(![string]::IsNullOrEmpty(($staticroute))){
                        $staticroute += ', '
                    }
                    $staticRoute += "$($route[0])=$($route[1])"
                }
            }

            $switchbinding = ""
            if($obj[6][1].count -gt 0){
                foreach($switch in $obj[6][1]){
                    if(![string]::IsNullOrEmpty(($switchbinding))){
                        $switchbinding += ', '
                    }
                    $switchbinding += "$($switch[0])=$($switch[1][1])"
                }
            }
            $result = New-Object PSObject -Property @{
                #uuid     = $obj[0][1]
                description  = $obj[1]
                enable = $obj[2]
                vnetid = $obj[3]
                staticroutes = $staticroute
                switchbinding = $switchbinding
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
