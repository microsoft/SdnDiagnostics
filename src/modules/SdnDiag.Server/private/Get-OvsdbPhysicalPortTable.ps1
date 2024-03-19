function Get-OvsdbPhysicalPortTable {
    <#
    .SYNOPSIS
        Returns a list of ports defined within the Physical_Port table of the OVSDB database.
    .EXAMPLE
        PS> Get-OvsdbPhysicalPortTable
    #>

    try {
        $arrayList = [System.Collections.ArrayList]::new()

        $ovsdbResults = Get-OvsdbDatabase -Table ms_vtep
        $portTable = $ovsdbResults | Where-Object { $_.caption -eq 'Physical_Port table' }

        if ($null -eq $portTable) {
            return $null
        }

        # enumerate the json objects and create psobject for each port
        foreach ($obj in $portTable.data) {
            $physicalPort = [OvsdbPhysicalPort]@{
                UUID        = $obj[0][1]
                Description = $obj[1]
                Name        = $obj[2].Trim('{', '}')  # remove the curly braces from the name
            }

            # there are numerous key/value pairs within this object with some having different properties
            # enumerate through the properties and add property and value for each
            foreach ($property in $obj[4][1]) {
                $physicalPort | Add-Member -MemberType NoteProperty -Name $property[0] -Value $property[1]
            }

            # add the psobject to array
            [void]$arrayList.Add($physicalPort)
        }

        return $arrayList
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
