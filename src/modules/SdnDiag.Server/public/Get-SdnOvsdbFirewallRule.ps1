function Get-SdnOvsdbFirewallRule {
    <#
    .SYNOPSIS
        Gets the firewall rules from OVSDB firewall database
    .PARAMETER RuleId
        The rule ID of the firewall rule to return. This is the InstanceID of the rule associated with accessControlLists from Network Controller.
    .PARAMETER VirtualNicId
        The virtual NIC ID of the firewall rule to return. This is the InstanceID of the Network Interface object from Network Controller.
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

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'RuleId')]
        [GUID]$RuleId,

        [Parameter(Mandatory = $false, ParameterSetName = 'VirtualNicId')]
        [GUID]$VirtualNicId,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'RuleId')]
        [Parameter(Mandatory = $false, ParameterSetName = 'VirtualNicId')]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'RuleId')]
        [Parameter(Mandatory = $false, ParameterSetName = 'VirtualNicId')]
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
        switch ($PSCmdlet.ParameterSetName) {
            'RuleId' { return ($results | Where-Object { $_.RuleId -eq $RuleId }) }
            'VirtualNicId' { return ($results | Where-Object { $_.VirtualNicId -eq $VirtualNicId }) }
            default { return $results }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
