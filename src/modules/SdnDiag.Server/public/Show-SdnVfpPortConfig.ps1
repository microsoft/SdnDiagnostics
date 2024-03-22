function Show-SdnVfpPortConfig {
    <#
    .SYNOPSIS
        Enumerates the VFP layers, groups and rules contained within Virtual Filtering Platform (VFP) for the specified port.
    .PARAMETER PortId
        The Port ID GUID for the network interface.
    .PARAMETER Direction
        Specify the direction
    .PARAMETER Type
        Specifies an array of IP address families. The cmdlet gets the configuration that matches the address families
    .EXAMPLE
        PS Show-SdnVfpPortConfig -PortId 8440FB77-196C-402E-8564-B0EF9E5B1931
    .EXAMPLE
        PS> Show-SdnVfpPortConfig -PortId 8440FB77-196C-402E-8564-B0EF9E5B1931 -Direction IN
    .EXAMPLE
        PS> Show-SdnVfpPortConfig -PortId 8440FB77-196C-402E-8564-B0EF9E5B1931 -Direction IN -Type IPv4
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [GUID]$PortId,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [ValidateSet('IPv4','IPv6')]
        [System.String]$Type,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [ValidateSet('IN','OUT')]
        [System.String]$Direction
    )

    try {
        $vfpLayers = Get-SdnVfpPortLayer -PortId $PortId
        if ($null -eq $vfpLayers) {
            "Unable to locate PortId {0}" -f $PortId | Trace-Output -Level:Error
            return $null
        }

        foreach ($layer in $vfpLayers) {
            "== Layer: {0} ==" -f $layer.LAYER | Write-Host -ForegroundColor:Magenta

            if ($Direction) {
                $vfpGroups = Get-SdnVfpPortGroup -PortId $PortId -Layer $layer.LAYER -Direction $Direction
            }
            else {
                $vfpGroups = Get-SdnVfpPortGroup -PortId $PortId -Layer $layer.LAYER
            }

            if ($Type) {
                $vfpGroups = $vfpGroups | Where-Object {$_.Type -ieq $Type}
            }

            foreach ($group in $vfpGroups) {
                "== Group: {0} ==" -f $group.GROUP | Write-Host -ForegroundColor:Yellow
                Get-SdnVfpPortRule -PortId $PortId -Layer $layer.LAYER -Group $group.GROUP | Format-Table -AutoSize
            }
        }
    }
    catch {
        $_ | Trace-Exception
    }
}
