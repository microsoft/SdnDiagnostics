function Get-OvsdbAddressMapping {
    <#
    .SYNOPSIS
        Returns a list of address mappings from within the OVSDB database.
    .EXAMPLE
        PS> Get-OvsdbAddressMapping
    #>

    try {
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
            $mac = $caMapping[0]
            $uuid = $caMapping[1][1]
            $ca = $caMapping[2]
            $locator = $caMapping[3][1]
            $logicalSwitch = $caMapping[4][1]
            $mappingType = $caMapping[5]

            $pa = [string]::Empty
            $encapType = [string]::Empty
            $rdid = [string]::Empty
            $vsid = 0

            # Get PA from locator table
            foreach ($paMapping in $paMappingTable.Data) {
                $curLocator = $paMapping[0][1]
                if ($curLocator -eq $locator) {
                    $pa = $paMapping[3]
                    $encapType = $paMapping[4]
                    break
                }
            }

            # Get Rdid and VSID from logical switch table
            foreach ($switch in $logicalSwitchTable.Data) {
                $curSwitch = $switch[0][1]
                if ($curSwitch -eq $logicalSwitch) {
                    $rdid = $switch[1]
                    $vsid = $switch[3]
                    break
                }
            }

            # create the psobject now that we have all the mappings identified
            $result = New-Object PSObject -Property @{
                UUID            = $uuid
                CustomerAddress = $ca
                ProviderAddress = $pa
                MAC             = $mac
                RoutingDomainID = $rdid
                VirtualSwitchID = $vsid
                MappingType     = $mappingType
                EncapType       = $encapType
            }

            # add the psobject to the array
            [void]$arrayList.Add($result)
        }

        return $arrayList
    }
    catch {
        $_ | Trace-Exception
    }
}
