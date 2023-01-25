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

    [System.Guid]$portProfileFeatureId = "9940cd46-8b06-43bb-b9d5-93d50381fd56"

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

        foreach ($adapter in $netAdapters | Where-Object { $_.IsManagementOs -eq $false }) {
            "Enumerating port features and data for adapter {0}" -f $adapter.MacAddress | Trace-Output -Level:Verbose
            $currentProfile = Get-VMSwitchExtensionPortFeature -FeatureId $portProfileFeatureId -VMNetworkAdapter $adapter
            if ($null -eq $currentProfile) {
                "{0} attached to {1} does not have a port profile" -f $adapter.MacAddress, $adapter.VMName | Trace-Output -Level:Warning
                continue
            }

            $object = [PSCustomObject]@{
                VMName      = $adapter.VMName
                Name        = $adapter.Name
                MacAddress  = $adapter.MacAddress
                ProfileId   = $currentProfile.SettingData.ProfileId
                ProfileData = $currentProfile.SettingData.ProfileData
            }

            $portData = (Get-VMSwitchExtensionPortData -VMNetworkAdapter $adapter)

            # we will typically see multiple port data values for each adapter, however the deviceid should be the same across all of the objects
            # defensive coding in place for situation where vm is not in proper state and this portdata is null
            if ($portData) {
                $object | Add-Member -MemberType NoteProperty -Name 'PortId' -Value $portData[0].data.deviceid
            }
            else {
                $object | Add-Member -MemberType NoteProperty -Name 'PortId' -Value $null
            }

            [void]$arrayList.Add($object)
        }

        return ($arrayList | Sort-Object -Property Name)
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
