function Get-NetworkInterfaceEncapOverheadSetting {
    <#
    .SYNOPSIS
        Retrieves the EncapOverhead and JumboPacket properties of each network interface attached to vmswitch
    #>

    try {
        $switchArrayList = [System.Collections.ArrayList]::new()

        foreach ($switch in (Get-VMSwitch)) {
            $interfaceArrayList = [System.Collections.ArrayList]::new()
            $supportsEncapOverhead = $false
            $encapOverheadValue = $null
            $supportsJumboPacket = $false
            $jumboPacketValue = $null
    
            # enumerate each of the physical network adapters that are bound to the vmswitch
            foreach ($physicalNicIfDesc in $switch.NetAdapterInterfaceDescriptions) {
    
                # get the encap overhead settings for each of the network interfaces within the vm switch team
                $encapOverhead = Get-NetAdapterAdvancedProperty -InterfaceDescription $physicalNicIfDesc -RegistryKeyword "*Encapoverhead" -ErrorAction SilentlyContinue
                if ($null -eq $encapoverhead) {
                    "Network interface {0} does not support EncapOverhead." -f $physicalNicIfDesc | Trace-Output -Level:Warning
                }
                else {
                    $supportsEncapOverhead = $true
                    [int]$encapOverheadValue = $encapoverhead.DisplayValue
                }
                
                # get the jumbo packet settings for each of the network interfaces within the vm switch team
                $jumboPacket = Get-NetAdapterAdvancedProperty -InterfaceDescription $physicalNicIfDesc -RegistryKeyword "*JumboPacket" -ErrorAction SilentlyContinue
                if ($null -eq $jumboPacket) {
                    "Network interface {0} does not support JumboPacket." -f $physicalNicIfDesc | Trace-Output -Level:Warning
                }
                else {
                    $supportsJumboPacket = $true
                    [int]$jumboPacketValue = $jumboPacket.RegistryValue[0]
                }

                $object = [PSCustomObject]@{
                    Switch               = $switch.Name
                    NetworkInterface     = $physicalNicIfDesc
                    EncapOverheadEnabled = $supportsEncapOverhead
                    EncapOverheadValue   = $encapOverheadValue
                    JumboPacketEnabled   = $supportsJumboPacket
                    JumboPacketValue     = $jumboPacketValue
                }
    
                # add each network interface to the interface arraylist
                [void]$interfaceArrayList.Add($object)
            }
    
            # add each of the switches to the switch hash table
            [void]$switchArrayList.Add($interfaceArrayList)
        }
    
        return $switchArrayList
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
