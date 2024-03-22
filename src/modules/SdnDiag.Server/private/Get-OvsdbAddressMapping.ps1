function Get-OvsdbAddressMapping {
    <#
    .SYNOPSIS
        Returns a list of address mappings from within the OVSDB database.
    .EXAMPLE
        PS> Get-OvsdbAddressMapping
    #>

    $arrayList = [System.Collections.ArrayList]::new()

    $ovsdbResults = Get-OvsdbDatabase -Table ms_vtep
    $paMappingTable = $ovsdbResults | Where-Object { $_.caption -eq 'Physical_Locator table' }
    $caMappingTable = $ovsdbResults | Where-Object { $_.caption -eq 'Ucast_Macs_Remote table' }
    $logicalSwitchTable = $ovsdbResults | Where-Object { $_.caption -eq 'Logical_Switch table' }

    if ($null -eq $caMappingTable) {
        return $null
    }

    # enumerate the json rules for each of the tables and create psobject for the mappings
    # unfortunately these values do not return in key/value pair and need to manually map each property
    foreach ($caMapping in $caMappingTable.Data) {

        # create the object
        $addressMapping = [OvsdbAddressMapping]@{
            UUID            = $caMapping[1][1]
            CustomerAddress = $caMapping[2]
            MacAddress      = $caMapping[0]
            MappingType     = $caMapping[5]
        }

        $locator = $caMapping[3][1]
        $logicalSwitch = $caMapping[4][1]

        # Get PA from locator table
        foreach ($paMapping in $paMappingTable.Data) {
            $curLocator = $paMapping[0][1]
            if ($curLocator -eq $locator) {
                $addressMapping.ProviderAddress = $paMapping[3]
                $addressMapping.EncapType = $paMapping[4]
                break
            }
        }

        # Get Rdid and VSID from logical switch table
        foreach ($switch in $logicalSwitchTable.Data) {
            $curSwitch = $switch[0][1]
            if ($curSwitch -eq $logicalSwitch) {
                $addressMapping.RoutingDomainId = $switch[1]
                $addressMapping.VSwitchID = $switch[3]
                break
            }
        }

        # add the object to the array
        [void]$arrayList.Add($addressMapping)
    }

    return $arrayList
}
