function Get-OvsdbFirewallRuleTable {
    <#
    .SYNOPSIS
        Returns a list of firewall rules defined within the firewall table of the OVSDB database.
    .EXAMPLE
        PS> Get-OvsdbFirewallRuleTable
    #>

    $arrayList = [System.Collections.ArrayList]::new()

    $ovsdbResults = Get-OvsdbDatabase -Table ms_firewall
    $firewallTable = $ovsdbResults | Where-Object { $_.caption -eq 'FW_Rules table' }

    if ($null -eq $firewallTable) {
        return $null
    }
    # enumerate the json rules and create object for each firewall rule returned
    # there is no nice way to generate this and requires manually mapping as only the values are return
    foreach ($obj in $firewallTable.data) {
        $result = [OvsdbFirewallRule]@{
            UUID               = $obj[0][1]
            Action             = $obj[1]
            Direction          = $obj[2]
            DestinationAddress = $obj[3]
            DestinationPort    = $obj[4]
            Logging            = $obj[5]
            Priority           = $obj[6]
            Protocols          = $obj[7]
            RuleId             = $obj[8]
            State              = $obj[9]
            Type               = $obj[10]
            SourceAddress      = $obj[11]
            SourcePort         = $obj[12]
            VirtualNicId       = $obj[13]
        }

        # add the psobject to array list
        [void]$arrayList.Add($result)
    }

    return $arrayList
}
