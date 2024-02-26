function Get-SdnVfpPortGroup {
    <#
    .SYNOPSIS
        Enumerates the groups contained within the specific Virtual Filtering Platform (VFP) layer specified for the port.
    .PARAMETER PortId
        The Port ID GUID for the network interface.
    .PARAMETER Layer
        Specify the target layer.
    .PARAMETER Direction
        Specify the direction
    .PARAMETER Type
        Specifies an array of IP address families. The cmdlet gets the configuration that matches the address families
    .PARAMETER Name
        Returns the specific group name. If omitted, will return all groups within the VFP layer.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of a remote computer. The default is the local computer.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnVfpPortGroup -PortId '2152523D-333F-4082-ADE4-107D8CA75F5B' -Layer 'SLB_NAT_LAYER'
    .EXAMPLE
        PS> Get-SdnVfpPortGroup -PortId '2152523D-333F-4082-ADE4-107D8CA75F5B' -Layer 'SLB_NAT_LAYER' -Name 'SLB_GROUP_NAT_IPv4_IN'
    .EXAMPLE
        PS> Get-SdnVfpPortGroup -PortId '2152523D-333F-4082-ADE4-107D8CA75F5B' -Layer 'SLB_NAT_LAYER' -Direction 'IN'
    .EXAMPLE
        PS> Get-SdnVfpPortGroup -PortId '2152523D-333F-4082-ADE4-107D8CA75F5B' -Layer 'SLB_NAT_LAYER' -Type 'IPv4'
    .EXAMPLE
        PS> Get-SdnVfpPortGroup -PortId '2152523D-333F-4082-ADE4-107D8CA75F5B' -Layer 'SLB_NAT_LAYER' -Direction 'IN' -Type 'IPv4'
    .EXAMPLE
        PS> Get-SdnVfpPortGroup -PortId '2152523D-333F-4082-ADE4-107D8CA75F5B' -Layer 'SLB_NAT_LAYER' -ComputerName 'RemoteComputer' -Credential (Get-Credential)
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Name')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [GUID]$PortId,

        [Parameter(Mandatory = $true, ParameterSetName = 'Name')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [System.String]$Layer,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [ValidateSet('IN','OUT')]
        [System.String]$Direction,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [ValidateSet('IPv4','IPv6')]
        [System.String]$Type,

        [Parameter(Mandatory = $false, ParameterSetName = 'Name')]
        [System.String]$Name,

        [Parameter(Mandatory = $false, ParameterSetName = 'Name')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [string]$ComputerName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Name')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $params = @{
            PortId = $PortId
            Layer = $Layer
        }

        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            $results = Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
                param ([guid]$arg0, [string]$arg1)
                Get-VfpPortGroup -PortId $arg0 -Layer $arg1
            } -ArgumentList @($params.PortId, $params.Layer)
        }
        else {
            $results = Get-VfpPortGroup @params
        }


        switch ($PSCmdlet.ParameterSetName) {
            'Name' {
                return ($results | Where-Object { $_.Group -eq $Name })
            }

            'Default' {
                if ($Type) {
                    $results = $results | Where-Object {$_.Type -ieq $Type}
                }
                if ($Direction) {
                    $results = $results | Where-Object {$_.Direction -ieq $Direction}
                }

                return ($results | Sort-Object -Property Priority)
            }
        }

        return $results
    }
    catch {
        $_ | Trace-Exception
    }
}
