function Get-SdnRole {
    <#
    .SYNOPSIS
        Retrieve the SDN Role for a given computername
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline)]
        [System.String]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Object]$EnvironmentInfo
    )

    # get the NetBIOS and FQDN name of the computer
    $result = Get-ComputerNameFQDNandNetBIOS -ComputerName $ComputerName

    # enumerate the objects for each of the available SDN roles to find a match
    # once match is found, return the role name as string back to calling function
    foreach ($role in $EnvironmentInfo.Keys) {
        if ($role -ieq 'FabricNodes') {
            continue
        }

        foreach ($object in $EnvironmentInfo[$role]) {
            if ($object -ieq $result.ComputerNameNetBIOS -or $object -ieq $result.ComputerNameFQDN) {
                return $role.ToString()
            }
        }
    }

    # if we made it to here, we were unable to locate any specific SdnRole such as LoadBalancerMux, Gateway, etc.
    # so instead we will return Common as the role
    return ([string]"Common")
}
