# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Set-VMNetworkAdapterPortProfile {
    <#
    .SYNOPSIS
        Configures the port profile applied to the virtual machine network interfaces.
    .PARAMETER VMName
        Specifies the name of the virtual machine.
    .PARAMETER MacAddress
        Specifies the MAC address of the VM network adapter.
    .PARAMETER ProfileId
        The InstanceID of the Network Interface taken from Network Controller.
    .PARAMETER ProfileData
        1 = VfpEnabled, 2 = VfpDisabled (usually in the case of Mux). If ommited, defaults to 1.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$VMName,

        [Parameter(Mandatory = $true)]
        [System.String]$MacAddress,

        [Parameter(Mandatory = $true)]
        [System.Guid]$ProfileId,

        [Parameter(Mandatory = $false)]
        [System.Int16]$ProfileData = 1
    )

    [System.Guid]$portProfileFeatureId = "9940cd46-8b06-43bb-b9d5-93d50381fd56"
    [System.Guid]$vendorId  = "1FA41B39-B444-4E43-B35A-E1F7985FD548"

    try {
        if ($null -eq (Get-Module -Name Hyper-V)) {
            Import-Module -Name Hyper-V -Force
        }

        $vmNic = Get-VMNetworkAdapter -VMName $VmName | Where-Object {$_.MacAddress -ieq $MacAddress}
        if ($null -eq $vmNic) {
            "Unable to locate VMNetworkAdapter" | Trace-Output -Level:Exception
            return
        }

        $portProfileDefaultSetting = Get-VMSystemSwitchExtensionPortFeature -FeatureId $portProfileFeatureId -ErrorAction Stop
        $portProfileDefaultSetting.SettingData.ProfileId = $ProfileId.ToString("B")
        $portProfileDefaultSetting.SettingData.NetCfgInstanceId = "{56785678-a0e5-4a26-bc9b-c0cba27311a3}"
        $portProfileDefaultSetting.SettingData.CdnLabelString = "TestCdn"
        $portProfileDefaultSetting.SettingData.CdnLabelId = 1111
        $portProfileDefaultSetting.SettingData.ProfileName = "Testprofile"
        $portProfileDefaultSetting.SettingData.VendorId = $vendorId.ToString("B")
        $portProfileDefaultSetting.SettingData.VendorName = "NetworkController"
        $portProfileDefaultSetting.SettingData.ProfileData = $ProfileData

        $currentProfile = Get-VMSwitchExtensionPortFeature -FeatureId $portProfileFeatureId -VMNetworkAdapter $vmNic
        if ($null -eq $currentProfile) {
            "Port profile not previously configured" | Trace-Output
            Add-VMSwitchExtensionPortFeature -VMSwitchExtensionFeature  $portProfileDefaultSetting -VMNetworkAdapter $vmNic
        }
        else {
            "Current Settings: ProfileId [{0}] ProfileData [{1}]" -f $currentProfile.SettingData.ProfileId, $currentProfile.SettingData.ProfileData | Trace-Output

            $currentProfile.SettingData.ProfileId = $ProfileId.ToString("B")
            $currentProfile.SettingData.ProfileData = $ProfileData
            $currentProfile.SettingData.VendorId = $vendorId.ToString("B")

            Set-VMSwitchExtensionPortFeature -VMSwitchExtensionFeature $currentProfile -VMNetworkAdapter $vmNic
        }

        "Successfully created/added Port Profile for VM [{0})], Adapter [{1}], PortProfileId [{2}], ProfileData [{3}]" -f $vmNic.VMName, $vmNic.Name, $ProfileId.ToString(), $ProfileData | Trace-Output
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
