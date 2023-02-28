# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Format-MacAddressNoDashes {
    <#
    .SYNOPSIS
        Returns a consistent MAC address back formatted without dashes
    .PARAMETER MacAddress
        MAC Address to canonicalize into standard format
    #>
    param (
        [System.String]$MacAddress
    )

    "Processing {0}" -f $MacAddress | Trace-Output -Level:Verbose

    if($MacAddress.Split('-').Count -eq 6){
        foreach($obj in $MacAddress.Split('-')){
            if($obj.Length -ne 2){
                throw New-Object System.ArgumentOutOfRangeException("Invalid MAC Address. Unable to split into expected pairs")
            }
        }
    }

    $MacAddress = $MacAddress.Replace('-','').Trim().ToUpper()
    return ($MacAddress.ToString())
}
