function Get-ManagementAddressOnly {
    param (
        $ManagementAddress
    )

    $uniqueFQDN = @()
    $uniqueIPAddress = @()

    foreach ($ma in $ManagementAddress) {
        $isIpAddress = ($ma -as [IPAddress]) -as [Bool]
        if ($isIpAddress) {
            $uniqueIPAddress += $ma
        }
        else {
            $uniqueFQDN += $ma.ToLower()
        }
    }

    # if we have a mix of FQDN and IPAddress, defer to FQDN
    # use Sort-Object -Unique to remove duplicates from the list (case insensitive)
    if ($uniqueFQDN) {
        return ($uniqueFQDN | Sort-Object -Unique)
    }
    else {
        return ($uniqueIPAddress | Sort-Object -Unique)
    }
}
