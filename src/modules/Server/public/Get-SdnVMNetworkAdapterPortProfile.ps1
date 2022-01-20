# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnVMNetworkAdapterPortProfile {
    <#
    .SYNOPSIS
        Retrieves the port profile applied to the virtual machine network interfaces.
    .PARAMETER VMName
        Specifies the name of the virtual machine to be retrieved.
    .PARAMETER AllVMs
        Switch to indicate to get all the virtual machines network interfaces on the hypervisor host.
    .PARAMETER HostVmNic
        When true, displays Port Profiles of Host VNics. Otherwise displays Port Profiles of Vm VNics.
    .EXAMPLE
        Get-SdnVMNetworkAdapterPortProfile -VMName 'VM01'
    .EXAMPLE
        Get-SdnVMNetworkAdapterPortProfile -AllVMs
    #>

    [CmdletBinding(DefaultParameterSetName = 'SingleVM')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'SingleVM')]
        [System.String]$VMName,

        [Parameter(Mandatory = $true, ParameterSetName = 'AllVMs')]
        [Switch]$AllVMs,

        [Parameter(ParameterSetName = 'SingleVM', Mandatory = $false)]
        [Parameter(ParameterSetName = 'AllVMs', Mandatory = $false)]
        [switch]$HostVmNic
    )

    $portProfileFeatureId = '9940cd46-8b06-43bb-b9d5-93d50381fd56'

    try {
        if ($null -eq (Get-Module -Name Hyper-V)) {
            Import-Module -Name Hyper-V -Force
        }

        $arrayList = [System.Collections.ArrayList]::new()

        if ($AllVMs) {
            $netAdapters = Get-VMNetworkAdapter -All | Where-Object { $_.IsManagementOs -eq $HostVmNic }
        }
        else {
            $netAdapters = Get-VMNetworkAdapter -VMName $VMName | Where-Object { $_.IsManagementOs -eq $HostVmNic }
        }

        foreach ($adapter in $netAdapters) {
            $currentProfile = Get-VMSwitchExtensionPortFeature -FeatureId $portProfileFeatureId -VMNetworkAdapter $adapter
            if ($null -eq $currentProfile) {
                "{0} attached to {1} does not have a port profile" -f $adapter.MacAddress, $adapter.VMName | Trace-Output -Level:Warning
                continue
            }

            $portId = (Get-VMSwitchExtensionPortData -VMNetworkAdapter $adapter)[0].data.deviceid
            $object = [PSCustomObject]@{
                VMName     = $adapter.VMName
                Name       = $adapter.Name
                MacAddress = $adapter.MacAddress
                PortId     = $portId
                ProfileId  = $currentProfile.SettingData.ProfileId
                Data       = $currentProfile.SettingData.ProfileData
            }

            [void]$arrayList.Add($object)
        }

        return ($arrayList | Sort-Object -Property Name)
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
