function Get-SdnRole {
    <#
        .SYNOPSIS
        Retrieve the SDN Role for a given computername

        .PARAMETER ComputerName
        Type the NetBIOS name or a fully qualified domain name of a computer.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$ComputerName
    )

    if ($null -eq $Global:SdnDiagnostics.EnvironmentInfo.NetworkController) {
        "Unable to enumerate data from EnvironmentInfo. Please run 'Get-SdnInfrastructureInfo' to populate infrastructure details." | Trace-Output -Level:Warning
        return
    }

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

    # enumerate the objects for each of the available SDN roles to find a match
    # once match is found, return the role name as string back to calling function
    foreach ($role in ($Global:SdnDiagnostics.EnvironmentInfo.Keys | Where-Object {$_ -iin $Global:SdnDiagnostics.Config.Keys})) {
        foreach ($object in $Global:SdnDiagnostics.EnvironmentInfo[$role]) {
            if ($object -ieq $computerNameNetBIOS -or $object -ieq $computerNameFQDN) {
                return $role.ToString()
            }
        }
    }

    # if we made it to here, we were unable to locate the appropriate role the computername is associated with
    "Unable to determine SDN role for {0}" -f $ComputerName | Trace-Output -Level:Warning
    return $null
}
