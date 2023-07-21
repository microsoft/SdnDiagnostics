function Format-MacAddress {
    <#
    .SYNOPSIS
        Returns a consistent MAC address back formatted with or without dashes
    .PARAMETER MacAddress
        MAC Address to canonicalize into standard format
    .PARAMETER Dashes
        Optional. If specified, the MAC address will be formatted with dashes
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
