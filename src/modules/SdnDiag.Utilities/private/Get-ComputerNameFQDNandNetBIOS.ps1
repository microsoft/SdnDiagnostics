function Get-ComputerNameFQDNandNetBIOS {
    <#
    .SYNOPSIS
        Returns back the NetBIOS and FQDN name of the computer
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline)]
        [System.String]$ComputerName
    )

    # we know Windows has some strict requirements around NetBIOS/DNS name of the computer
    # so we can safely make some assumptions that if period (.) exists, then assume the ComputerName being passed into function
    # is a FQDN in which case we want to split the string and assign the NetBIOS name
    if ($ComputerName.Contains('.')) {
        [System.String]$computerNameNetBIOS = $ComputerName.Split('.')[0]
        [System.String]$computerNameFQDN = $ComputerName
    }

    # likewise, if no period (.) specified as part of the ComputerName we can assume we were passed a NetBIOS name of the object
    # in which case we will try to resolve via DNS. If any failures when resolving the HostName from DNS, will catch and default to
    # current user dns domain in best effort
    else {
        [System.String]$computerNameNetBIOS = $ComputerName
        try {
            [System.String]$computerNameFQDN = [System.Net.Dns]::GetHostByName($ComputerName).HostName
        }
        catch {
            [System.String]$computerNameFQDN = "$($ComputerName).$($env:USERDNSDOMAIN)"
        }
    }

    return [PSCustomObject]@{
        ComputerNameNetBIOS = $computerNameNetBIOS
        ComputerNameFQDN    = $computerNameFQDN
    }
}
