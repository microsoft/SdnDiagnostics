function Get-SdnVfpPortLayer {
    <#
    .SYNOPSIS
        Enumerates the layers contained within Virtual Filtering Platform (VFP) for specified for the port.
    .PARAMETER PortId
        The Port ID GUID for the network interface
    .PARAMETER Name
        Returns the specific layer name. If omitted, will return all layers within VFP.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of a remote computer. The default is the local computer.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnVfpPortLayer
    .EXAMPLE
        PS> Get-SdnVfpPortLayer -PortId '2152523D-333F-4082-ADE4-107D8CA75F5B'
    .EXAMPLE
        PS> Get-SdnVfpPortLayer -PortId '2152523D-333F-4082-ADE4-107D8CA75F5B' -ComputerName SDN-HOST01 -Credential (Get-Credential)
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true)]
        [GUID]$PortId,

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
        }

        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            $results = Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
                param([guid]$arg0)
                Get-VfpPortLayer -PortId $arg0
            } -ArgumentList $params
        }
        else {
            $results = Get-VfpPortLayer @params
        }

        if ($Name) {
            return ($results | Where-Object { $_.Layer -eq $Name })
        }

        return $results
    }
    catch {
       $_ | Trace-Output -Level:Error
    }
}
