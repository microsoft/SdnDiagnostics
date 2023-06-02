function Get-SdnOvsdbFirewallRule {
    <#
    .SYNOPSIS
        Gets the firewall rules from OVSDB firewall database
    .PARAMETER RuleId
        The rule ID of the firewall rule to return. This is the InstanceID of the rule associated with accessControlLists from Network Controller.
    .PARAMETER VirtualNicId
        The virtual NIC ID of the firewall rule to return. This is the InstanceID of the ipConfiguration associated with networkInterfaces from Network Controller.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnOvsdbFirewallRule -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Get-SdnOvsdbFirewallRule -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnOvsdbFirewallRule -RuleId '2152523D-333F-4082-ADE4-107D8CA75F5B' -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Get-SdnOvsdbFirewallRule -VirtualNicId '2152523D-333F-4082-ADE4-107D8CA75F5B' -ComputerName 'Server01'
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [GUID]$RuleId,

        [Parameter(Mandatory = $false)]
        [GUID]$VirtualNicId,

        [Parameter(Mandatory = $false)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            $results = Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock { Get-SdnOvsdbFirewallRule } -Credential $Credential
        }
        else {
            $results = Get-OvsdbFirewallRuleTable
        }

        # filter the results to only return the rules that match the specified parameters
        if ($PSBoundParameters.ContainsKey('RuleId')) {
            $results = $results | Where-Object { $_.RuleId -eq $RuleId }
        }

        if ($PSBoundParameters.ContainsKey('VirtualNicId')) {
            # convert the GUID to a string in the format of 32 digits separated by hyphens, enclosed in braces to align with the format of the table data
            # refer to https://learn.microsoft.com/en-us/dotnet/api/system.guid.tostring for the format of the string
            $results = $results | Where-Object { $_.VirtualNicId -eq $VirtualNicId.ToString("B") }
        }

        return $results
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
