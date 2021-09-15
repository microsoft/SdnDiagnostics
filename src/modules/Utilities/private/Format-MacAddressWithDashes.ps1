function Format-MacAddressWithDashes {
    <#
    .SYNOPSIS
        Returns a consistent MAC address back formatted with dashes
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

        return ($MacAddress.ToString().ToUpper())
    }
    
    if($MacAddress.Length -ne 12){
        throw New-Object System.ArgumentOutOfRangeException("Invalid MAC Address. Length is not equal to 12 ")
    }
    else {
        $MacAddress = $MacAddress.Insert(2,"-").Insert(5,"-").Insert(8,"-").Insert(11,"-").Insert(14,"-").Trim().ToUpper()
        return ($MacAddress.ToString())
    }
}
