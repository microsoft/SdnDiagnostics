function Get-SdnVfpPortLayer {
    <#
    .SYNOPSIS
        Enumerates the layers contained within Virtual Filtering Platform (VFP) for specified for the port.
    .PARAMETER PortId
        The Port ID GUID for the network interface
    .PARAMETER Name
        Returns the specific layer name. If omitted, will return all layers within VFP.
    .EXAMPLE
        PS> Get-SdnVfpPortLayer
    .EXAMPLE
        PS> Get-SdnVfpPortLayer -PortId '2152523D-333F-4082-ADE4-107D8CA75F5B'
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true)]
        [GUID]$PortId,

        [Parameter(Mandatory = $false)]
        [System.String]$Name,

        [Parameter(Mandatory = $false)]
        [string[]]$ComputerName,

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
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
