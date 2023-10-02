function Get-SdnNetAdapterEncapOverheadConfig {
    <#
    .SYNOPSIS
        Retrieves the EncapOverhead and JumboPacket properties of each network interface attached to a vfp enabled vmswitch
    .EXAMPLE
        PS> Get-SdnNetAdapterEncapOverheadConfig
    #>

    try {
        $switchArrayList = @()

        # filter to only look at vSwitches where the Microsoft Azure VFP Switch Extension is installed
        # once we have the vSwitches, then need to then filter and only look at switches where VFP is enabled
        $vfpSwitch = Get-VMSwitch | Where-Object {$_.Extensions.Id -ieq 'F74F241B-440F-4433-BB28-00F89EAD20D8'}
        foreach ($switch in $vfpSwitch) {
            $vfpExtension = $switch.Extensions | Where-Object {$_.Id -ieq 'F74F241B-440F-4433-BB28-00F89EAD20D8'}
            if ($vfpExtension.Enabled -ieq $false) {
                continue
            }

            $interfaceArrayList = @()
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

                # add each network interface to the interface array
                $interfaceArrayList += $object
            }

            # add each of the switches to the array
            $switchArrayList += $interfaceArrayList
        }

        return $switchArrayList
    }
    catch {
       $_ | Trace-Output -Level:Error
    }
}
