function Get-OvsdbFirewallRuleTable {
    <#
    .SYNOPSIS
        Returns a list of firewall rules from the SDN OVSDB servers
    #>

    try {
        $arrayList = [System.Collections.ArrayList]::new()

        $ovsdbResults = Get-OvsdbDatabase -Table ms_firewall
        $firewallTable = $ovsdbResults | Where-Object { $_.caption -eq 'FW_Rules table' }

        # enumerate the json rules and create object for each firewall rule returned
        # there is no nice way to generate this and requires manually mapping as only the values are return
        foreach ($obj in $firewallTable.data) {
            $result = New-Object PSObject -Property @{
                uuid             = $obj[0][1]
                action           = $obj[1]
                direction        = $obj[2]
                dst_ip_addresses = $obj[3]
                dst_ports        = $obj[4]
                logging_state    = $obj[5]
                priority         = $obj[6]
                protocols        = $obj[7]
                rule_id          = $obj[8]
                rule_state       = $obj[9]
                rule_type        = $obj[10]
                src_ip_addresses = $obj[11]
                src_ports        = $obj[12]
                vnic_id          = $obj[13].Trim('{', '}')
            }

            # add the psobject to array list
            [void]$arrayList.Add($result)
        }
        
        return $arrayList
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
