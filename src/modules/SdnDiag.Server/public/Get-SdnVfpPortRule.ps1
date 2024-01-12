function Get-SdnVfpPortRule {
    <#
    .SYNOPSIS
        Enumerates the rules contained within the specific group within Virtual Filtering Platform (VFP) layer specified for the port.
    .PARAMETER PortId
        The Port ID GUID for the network interface.
    .PARAMETER Layer
        Specify the target layer.
    .PARAMETER Group
        Specify the group layer.
    .PARAMETER Name
        Returns the specific rule name. If omitted, will return all rules within the VFP group.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of a remote computer. The default is the local computer.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnVfpPortRule -PortId '2152523D-333F-4082-ADE4-107D8CA75F5B' -Layer 'SLB_NAT_LAYER' -Group 'SLB_GROUP_NAT_IPv4_IN'
    .EXAMPLE
        PS> Get-SdnVfpPortRule -PortId '2152523D-333F-4082-ADE4-107D8CA75F5B' -Layer 'SLB_NAT_LAYER' -Group 'SLB_GROUP_NAT_IPv4_IN' -Name 'SLB_DEFAULT_RULE'
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [GUID]$PortId,

        [Parameter(Mandatory = $true)]
        [System.String]$Layer,

        [Parameter(Mandatory = $true)]
        [System.String]$Group,

        [Parameter(Mandatory = $false)]
        [System.String]$Name,

        [Parameter(Mandatory = $false)]
        [string]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $params = @{
            PortId = $PortId
            Layer = $Layer
            Group = $Group
        }

        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            $results = Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
                param([guid]$arg0, [string]$arg1, [string]$arg2)
                Get-VfpPortRule -PortId $arg0 -Layer $arg1 -Group $arg2
            } -ArgumentList $params
        }
        else {
            $results = Get-VfpPortRule @params
        }

        if ($Name) {
            return ($results | Where-Object {$_.Rule -ieq $Name -or $_.'FriendlyName' -ieq $Name})
        }

        return $results
    }
    catch {
        $_ | Trace-Exception
    }
}
