function Set-SdnVMNetworkAdapterPortProfile {
    <#
    .SYNOPSIS
        Configures the port profile applied to the virtual machine network interfaces.
    .PARAMETER VMName
        Specifies the name of the virtual machine.
    .PARAMETER MacAddress
        Specifies the MAC address of the VM network adapter.
    .PARAMETER ProfileId
        The InstanceID of the Network Interface taken from Network Controller. If ommited, defaults to an empty GUID to enable network connectivity for non-NC managed VMs.
    .PARAMETER ProfileData
        1 = VfpEnabled, 2 = VfpDisabled (usually in the case of Mux). If ommited, defaults to 1.
    .PARAMETER HostVmNic
        Indicates if NIC is a host NIC. If ommited, defaults to false.
    .PARAMETER HyperVHost
        Type the NetBIOS name, an IP address, or a fully qualified domain name of the computer that is hosting the virtual machine.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        Set-SdnVMNetworkAdapterPortProfile -VMName 'TestVM01' -MacAddress 001DD826100E -ProfileId <InstanceIDFromNC> -ProfileData 1
    .EXAMPLE
        Set-SdnVMNetworkAdapterPortProfile -VMName 'TestVM01' -MacAddress 001DD826100E -ProfileData 2
    #>

    [CmdletBinding(DefaultParameterSetName = 'Local')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Remote')]
        [System.String]$VMName,

        [Parameter(Mandatory = $true, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Remote')]
        [System.String]$MacAddress,

        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.Guid]$ProfileId = [System.Guid]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [Int]$ProfileData = 1,

        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [switch]$HostVmNic,

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.String]$HyperVHost,

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    function Set-VMNetworkAdapterPortProfile {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true, Position = 0)]
            [System.String]$VMName,

            [Parameter(Mandatory = $true, Position = 1)]
            [System.String]$MacAddress,

            [Parameter(Mandatory = $true, Position = 2)]
            [System.Guid]$ProfileId,

            [Parameter(Mandatory = $false, Position = 3)]
            [System.Int16]$ProfileData = 1,

            [Parameter(Mandatory = $false, Position = 4)]
            [switch]$HostVmNic
        )

        [System.Guid]$portProfileFeatureId = "9940cd46-8b06-43bb-b9d5-93d50381fd56"
        [System.Guid]$vendorId  = "1FA41B39-B444-4E43-B35A-E1F7985FD548"

        if ($null -eq (Get-Module -Name Hyper-V)) {
            Import-Module -Name Hyper-V -Force
        }

        if ($HostVmNic) {
            $vmNic = Get-VMNetworkAdapter -ManagementOS -VMName $VmName | Where-Object {$_.MacAddress -ieq $MacAddress}
        }
        else {
            $vmNic = Get-VMNetworkAdapter -VMName $VmName | Where-Object {$_.MacAddress -ieq $MacAddress}
        }

        if ($null -eq $vmNic) {
            "Unable to locate VMNetworkAdapter" | Trace-Output -Level:Error
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

    $splat = @{
        VMName = $VMName
        MacAddress = $MacAddress
        ProfileId = $ProfileId
        ProfileData = $ProfileData
        HostVmNic = $HostVmNic
    }

    try {
        switch ($PSCmdlet.ParameterSetName) {
            'Remote' {
                Invoke-PSRemoteCommand -ComputerName $HyperVHost -Credential $Credential -ScriptBlock {
                    param(
                        [Parameter(Position = 0)][String]$param1,
                        [Parameter(Position = 1)][String]$param2,
                        [Parameter(Position = 2)][Guid]$param3,
                        [Parameter(Position = 3)][Int]$param4,
                        [Parameter(Position = 4)][Switch]$param5
                    )

                    Set-VMNetworkAdapterPortProfile -VMName $param1 -MacAddress $param2 -ProfileId $param3 -ProfileData $param4
                } -ArgumentList @($splat.VMName, $splat.MacAddress, $splat.ProfileId, $splat.ProfileData, $splat.$HostVmNic)
            }
            'Local' {
                Set-VMNetworkAdapterPortProfile @splat
            }
        }
    }
    catch {
        $_ | Trace-Exception
    }
}
