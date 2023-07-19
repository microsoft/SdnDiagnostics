function Format-MacAddress {
    <#
    .SYNOPSIS
        Returns a consistent MAC address back formatted without dashes
    .PARAMETER MacAddress
        MAC Address to canonicalize into standard format
    #>
    param (
        [System.String]$MacAddress,
        [Switch]$Dashes
    )

    if ($Dashes) {
        return (Format-MacAddressWithDashes -MacAddress $MacAddress)
    }
    else {
        return (Format-MacAddressNoDashes -MacAddress $MacAddress)
    }
}
