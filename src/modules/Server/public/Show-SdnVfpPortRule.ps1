function Show-SdnVfpPortRule {
    <#
    .SYNOPSIS
        Enumerates the VFP layers, groups and rules contained within Virtual Filtering Platform (VFP) for the specified port.
    .PARAMETER PortId
        The Port ID GUID for the network interface.
    .PARAMETER Direction
        Specify the direction
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [GUID]$PortId,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [ValidateSet('IN','OUT')]
        [System.String]$Direction
    )

    try {
        $vfpLayers = Get-VfpPortLayer -PortId $PortId
        if ($null -eq $vfpLayers) {
            "Unable to locate PortId {0}" -f $PortId | Trace-Output -Level:Exception
            return $null
        }

        foreach ($layer in $vfpLayers) {
            "== Layer: {0} ==" -f $layer.LAYER | Write-Host -ForegroundColor:Magenta
            $vfpGroups = Get-VfpPortGroup -PortId $PortId -Layer $layer.LAYER -Direction $Direction
            foreach ($group in $vfpGroups) {
                "== Group: {0} ==" -f $group.GROUP | Write-Host -ForegroundColor:Yellow
                Get-VfpPortRule -PortId $PortId -Layer $layer.LAYER -Group $group.GROUP | Format-Table -AutoSize
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
