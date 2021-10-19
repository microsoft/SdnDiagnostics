# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-ComputerNameIsLocal {
    <##>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$ComputerName
    )

    try {
        # detect if the ComputerName passed is an IP address
        # if so, need to enumerate the IP addresses on the system to compare with ComputerName to determine if there is a match
        $isIpAddress = ($ComputerName -as [IPAddress]) -as [Bool]
        if($isIpAddress){
            $ipAddresses = Get-NetIPAddress
            foreach($ip in $ipAddresses){
                if([IPAddress]$ip.IpAddress -eq [IPAddress]$ComputerName){
                    return $true
                }
            }
        }

        # check to determine if the ComputerName matches the NetBIOS name of the computer
        if($env:COMPUTERNAME -ieq $ComputerName){
            return $true
        }

        # check to determine if ComputerName matches the FQDN name of the computer
        if(([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName) -ieq $ComputerName){
            return $true
        }

        return $false
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
