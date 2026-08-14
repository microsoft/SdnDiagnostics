Describe 'Server - Repair-SdnVMNetworkAdapterPortProfile' {

    BeforeAll {
        # the Hyper-V PowerShell module is not guaranteed to be present on the machine running the offline tests,
        # so we define stand-in enums that mirror Microsoft.HyperV.PowerShell.VMNetworkAdapterVlanMode and
        # Microsoft.HyperV.PowerShell.VMNetworkAdapterPrivateVlanMode. these are added to the AppDomain so that
        # they resolve from within the SdnDiag.Server module scope where the tests execute.
        if (-NOT ('SdnDiagnostics.PesterOffline.VMNetworkAdapterVlanMode' -as [type])) {
            Add-Type -TypeDefinition @'
namespace SdnDiagnostics.PesterOffline {
    public enum VMNetworkAdapterVlanMode { Untagged = 0, Access = 1, Trunk = 2, Private = 3 }
    public enum VMNetworkAdapterPrivateVlanMode { Isolated = 1, Community = 2, Promiscuous = 3 }
}
'@
        }

        # objects returned from a remote session are serialized and rehydrated by PSRemoting, which causes enum
        # properties such as OperationMode and PrivateVlanMode to be deserialized as their underlying integer
        # value rather than the enum itself. this helper round trips a mock object through the same serializer
        # that Invoke-Command uses, so that the remote host tests exercise the exact shape the function receives.
        function global:ConvertTo-PesterRemoteObject {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
                $InputObject
            )

            process {
                return [System.Management.Automation.PSSerializer]::Deserialize(
                    [System.Management.Automation.PSSerializer]::Serialize($InputObject, 1)
                )
            }
        }

        # the Hyper-V PowerShell module is not guaranteed to be present on the machine running the offline tests,
        # so we define test-only stubs for the Hyper-V cmdlets used by the local host code path. these are defined
        # in the global scope so that the mocks Pester injects into the SdnDiag.Server module scope take precedence.
        function global:Get-VMNetworkAdapterVlan {
            [CmdletBinding()]
            param (
                [Parameter(ValueFromPipeline = $true)]
                $VMNetworkAdapter
            )
        }

        function global:Set-VMNetworkAdapterVlan {
            [CmdletBinding()]
            param (
                [Parameter(ValueFromPipeline = $true)]
                $VMNetworkAdapter,

                [Parameter(Mandatory = $false)]
                [switch]$Untagged
            )
        }

        # network interface returned from Network Controller that the VM network adapter should be aligned to.
        # instanceId is a valid GUID so that it can be compared against the profileId returned from the hypervisor.
        $Global:PesterOfflineTests.RepairPortProfile = @{
            InstanceId       = '11111111-2222-3333-4444-555555555555'
            MacAddress       = '001DD8070001'
            NcUri            = 'https://dvlab-nc.dvlab.contoso.local'
            HyperVHost       = 'DVLAB-S1-N01'
            VMName           = 'DVLAB-VM01'
            NetworkInterface = [PSCustomObject]@{
                resourceRef = '/networkInterfaces/DVLAB-VM01-NIC01'
                instanceId  = '11111111-2222-3333-4444-555555555555'
                properties  = [PSCustomObject]@{
                    privateMacAddress = '001DD8070001'
                    ipConfigurations  = @(
                        [PSCustomObject]@{
                            properties = [PSCustomObject]@{
                                privateIPAllocationMethod = 'Static'
                                subnet                    = [PSCustomObject]@{ resourceRef = '/virtualNetworks/vnet-0001/subnets/subnet-0001' }
                            }
                        }
                    )
                }
            }
        }
    }

    AfterAll {
        Remove-Item -Path 'function:\global:Get-VMNetworkAdapterVlan' -Force -ErrorAction SilentlyContinue
        Remove-Item -Path 'function:\global:Set-VMNetworkAdapterVlan' -Force -ErrorAction SilentlyContinue
        Remove-Item -Path 'function:\global:ConvertTo-PesterRemoteObject' -Force -ErrorAction SilentlyContinue
    }

    Context 'Remote Hyper-V host' {

        It "Removes the VLAN configuration when the VM network adapter is configured with an access VLAN" {
            InModuleScope SdnDiag.Server {
                $testData = $Global:PesterOfflineTests.RepairPortProfile

                Mock Get-SdnResource -RemoveParameterType 'Resource' -MockWith { return $Global:PesterOfflineTests.RepairPortProfile.NetworkInterface }
                Mock Test-ComputerNameIsLocal { return $false }
                Mock Set-SdnVMNetworkAdapterPortProfile { }

                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Get-SdnVMNetworkAdapterPortProfile' } -MockWith {
                    return [PSCustomObject]@{
                        VMName      = $Global:PesterOfflineTests.RepairPortProfile.VMName
                        MacAddress  = $Global:PesterOfflineTests.RepairPortProfile.MacAddress
                        ProfileId   = "{$($Global:PesterOfflineTests.RepairPortProfile.InstanceId)}"
                        ProfileData = 1
                    }
                }

                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Get-SdnVMNetworkAdapterVlanCim' } -MockWith {
                    return ([PSCustomObject]@{
                        OperationMode = 'Access'
                        AccessVlanId  = 101
                    })
                }

                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Set-VMNetworkAdapterVlan' } -MockWith { }

                Repair-SdnVMNetworkAdapterPortProfile -VMName $testData.VMName -MacAddress $testData.MacAddress `
                    -NcUri $testData.NcUri -HyperVHost $testData.HyperVHost -WarningAction SilentlyContinue

                Should -Invoke -CommandName Invoke-SdnCommand -Exactly -Times 1 -ParameterFilter { $ScriptBlock.ToString() -match 'Set-VMNetworkAdapterVlan' }
            }
        }

        It "Removes the VLAN configuration when the VM network adapter is configured in trunk mode" {
            InModuleScope SdnDiag.Server {
                $testData = $Global:PesterOfflineTests.RepairPortProfile

                Mock Get-SdnResource -RemoveParameterType 'Resource' -MockWith { return $Global:PesterOfflineTests.RepairPortProfile.NetworkInterface }
                Mock Test-ComputerNameIsLocal { return $false }
                Mock Set-SdnVMNetworkAdapterPortProfile { }

                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Get-SdnVMNetworkAdapterPortProfile' } -MockWith {
                    return [PSCustomObject]@{
                        VMName      = $Global:PesterOfflineTests.RepairPortProfile.VMName
                        MacAddress  = $Global:PesterOfflineTests.RepairPortProfile.MacAddress
                        ProfileId   = "{$($Global:PesterOfflineTests.RepairPortProfile.InstanceId)}"
                        ProfileData = 1
                    }
                }

                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Get-SdnVMNetworkAdapterVlanCim' } -MockWith {
                    return ([PSCustomObject]@{
                        OperationMode           = 'Trunk'
                        NativeVlanId            = 0
                        AllowedVlanIdList       = @(1..100)
                        AllowedVlanIdListString = '1-100'
                    })
                }

                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Set-VMNetworkAdapterVlan' } -MockWith { }

                Repair-SdnVMNetworkAdapterPortProfile -VMName $testData.VMName -MacAddress $testData.MacAddress `
                    -NcUri $testData.NcUri -HyperVHost $testData.HyperVHost -WarningAction SilentlyContinue

                Should -Invoke -CommandName Invoke-SdnCommand -Exactly -Times 1 -ParameterFilter { $ScriptBlock.ToString() -match 'Set-VMNetworkAdapterVlan' }
            }
        }

        It "Removes the VLAN configuration when the VM network adapter is configured in private VLAN promiscuous mode" {
            InModuleScope SdnDiag.Server {
                $testData = $Global:PesterOfflineTests.RepairPortProfile

                Mock Get-SdnResource -RemoveParameterType 'Resource' -MockWith { return $Global:PesterOfflineTests.RepairPortProfile.NetworkInterface }
                Mock Test-ComputerNameIsLocal { return $false }
                Mock Set-SdnVMNetworkAdapterPortProfile { }

                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Get-SdnVMNetworkAdapterPortProfile' } -MockWith {
                    return [PSCustomObject]@{
                        VMName      = $Global:PesterOfflineTests.RepairPortProfile.VMName
                        MacAddress  = $Global:PesterOfflineTests.RepairPortProfile.MacAddress
                        ProfileId   = "{$($Global:PesterOfflineTests.RepairPortProfile.InstanceId)}"
                        ProfileData = 1
                    }
                }

                # when PrivateVlanMode is Promiscuous, SecondaryVlanId is not populated and the configured VLANs
                # are exposed via SecondaryVlanIdList / SecondaryVlanIdListString instead.
                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Get-SdnVMNetworkAdapterVlanCim' } -MockWith {
                    return ([PSCustomObject]@{
                        OperationMode             = 'Private'
                        PrivateVlanMode           = 'Promiscuous'
                        PrimaryVlanId             = 10
                        SecondaryVlanId           = 0
                        SecondaryVlanIdList       = @(11, 12)
                        SecondaryVlanIdListString = '11-12'
                    })
                }

                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Set-VMNetworkAdapterVlan' } -MockWith { }

                Repair-SdnVMNetworkAdapterPortProfile -VMName $testData.VMName -MacAddress $testData.MacAddress `
                    -NcUri $testData.NcUri -HyperVHost $testData.HyperVHost -WarningAction SilentlyContinue

                Should -Invoke -CommandName Invoke-SdnCommand -Exactly -Times 1 -ParameterFilter { $ScriptBlock.ToString() -match 'Set-VMNetworkAdapterVlan' }
            }
        }

        It "Removes the VLAN configuration when the VM network adapter is configured in private VLAN isolated mode" {
            InModuleScope SdnDiag.Server {
                $testData = $Global:PesterOfflineTests.RepairPortProfile

                Mock Get-SdnResource -RemoveParameterType 'Resource' -MockWith { return $Global:PesterOfflineTests.RepairPortProfile.NetworkInterface }
                Mock Test-ComputerNameIsLocal { return $false }
                Mock Set-SdnVMNetworkAdapterPortProfile { }

                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Get-SdnVMNetworkAdapterPortProfile' } -MockWith {
                    return [PSCustomObject]@{
                        VMName      = $Global:PesterOfflineTests.RepairPortProfile.VMName
                        MacAddress  = $Global:PesterOfflineTests.RepairPortProfile.MacAddress
                        ProfileId   = "{$($Global:PesterOfflineTests.RepairPortProfile.InstanceId)}"
                        ProfileData = 1
                    }
                }

                # when PrivateVlanMode is Isolated, SecondaryVlanId is populated and SecondaryVlanIdList is null.
                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Get-SdnVMNetworkAdapterVlanCim' } -MockWith {
                    return ([PSCustomObject]@{
                        OperationMode             = 'Private'
                        PrivateVlanMode           = 'Isolated'
                        PrimaryVlanId             = 10
                        SecondaryVlanId           = 11
                        SecondaryVlanIdList       = $null
                        SecondaryVlanIdListString = $null
                    })
                }

                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Set-VMNetworkAdapterVlan' } -MockWith { }

                Repair-SdnVMNetworkAdapterPortProfile -VMName $testData.VMName -MacAddress $testData.MacAddress `
                    -NcUri $testData.NcUri -HyperVHost $testData.HyperVHost -WarningAction SilentlyContinue

                Should -Invoke -CommandName Invoke-SdnCommand -Exactly -Times 1 -ParameterFilter { $ScriptBlock.ToString() -match 'Set-VMNetworkAdapterVlan' }
            }
        }

        It "Does not modify the VLAN configuration when the VM network adapter is untagged" {
            InModuleScope SdnDiag.Server {
                $testData = $Global:PesterOfflineTests.RepairPortProfile

                Mock Get-SdnResource -RemoveParameterType 'Resource' -MockWith { return $Global:PesterOfflineTests.RepairPortProfile.NetworkInterface }
                Mock Test-ComputerNameIsLocal { return $false }
                Mock Set-SdnVMNetworkAdapterPortProfile { }

                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Get-SdnVMNetworkAdapterPortProfile' } -MockWith {
                    return [PSCustomObject]@{
                        VMName      = $Global:PesterOfflineTests.RepairPortProfile.VMName
                        MacAddress  = $Global:PesterOfflineTests.RepairPortProfile.MacAddress
                        ProfileId   = "{$($Global:PesterOfflineTests.RepairPortProfile.InstanceId)}"
                        ProfileData = 1
                    }
                }

                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Get-SdnVMNetworkAdapterVlanCim' } -MockWith {
                    return ([PSCustomObject]@{
                        OperationMode = 'Untagged'
                        AccessVlanId  = 0
                    })
                }

                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Set-VMNetworkAdapterVlan' } -MockWith { }

                Repair-SdnVMNetworkAdapterPortProfile -VMName $testData.VMName -MacAddress $testData.MacAddress `
                    -NcUri $testData.NcUri -HyperVHost $testData.HyperVHost

                Should -Invoke -CommandName Invoke-SdnCommand -Exactly -Times 0 -ParameterFilter { $ScriptBlock.ToString() -match 'Set-VMNetworkAdapterVlan' }
                Should -Invoke -CommandName Set-SdnVMNetworkAdapterPortProfile -Exactly -Times 0
            }
        }

        It "Repairs the port profile when the profile data does not match and the adapter is untagged" {
            InModuleScope SdnDiag.Server {
                $testData = $Global:PesterOfflineTests.RepairPortProfile

                Mock Get-SdnResource -RemoveParameterType 'Resource' -MockWith { return $Global:PesterOfflineTests.RepairPortProfile.NetworkInterface }
                Mock Test-ComputerNameIsLocal { return $false }
                Mock Set-SdnVMNetworkAdapterPortProfile { }

                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Get-SdnVMNetworkAdapterPortProfile' } -MockWith {
                    return [PSCustomObject]@{
                        VMName      = $Global:PesterOfflineTests.RepairPortProfile.VMName
                        MacAddress  = $Global:PesterOfflineTests.RepairPortProfile.MacAddress
                        ProfileId   = "{$($Global:PesterOfflineTests.RepairPortProfile.InstanceId)}"
                        ProfileData = 2
                    }
                }

                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Get-SdnVMNetworkAdapterVlanCim' } -MockWith {
                    return ([PSCustomObject]@{
                        OperationMode = 'Untagged'
                        AccessVlanId  = 0
                    })
                }

                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Set-VMNetworkAdapterVlan' } -MockWith { }

                Repair-SdnVMNetworkAdapterPortProfile -VMName $testData.VMName -MacAddress $testData.MacAddress `
                    -NcUri $testData.NcUri -HyperVHost $testData.HyperVHost

                Should -Invoke -CommandName Set-SdnVMNetworkAdapterPortProfile -Exactly -Times 1
                Should -Invoke -CommandName Invoke-SdnCommand -Exactly -Times 0 -ParameterFilter { $ScriptBlock.ToString() -match 'Set-VMNetworkAdapterVlan' }
            }
        }

        It "Removes the VLAN configuration and repairs the port profile when both are misconfigured" {
            InModuleScope SdnDiag.Server {
                $testData = $Global:PesterOfflineTests.RepairPortProfile

                Mock Get-SdnResource -RemoveParameterType 'Resource' -MockWith { return $Global:PesterOfflineTests.RepairPortProfile.NetworkInterface }
                Mock Test-ComputerNameIsLocal { return $false }
                Mock Set-SdnVMNetworkAdapterPortProfile { }

                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Get-SdnVMNetworkAdapterPortProfile' } -MockWith {
                    return [PSCustomObject]@{
                        VMName      = $Global:PesterOfflineTests.RepairPortProfile.VMName
                        MacAddress  = $Global:PesterOfflineTests.RepairPortProfile.MacAddress
                        ProfileId   = '{00000000-0000-0000-0000-000000000000}'
                        ProfileData = 2
                    }
                }

                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Get-SdnVMNetworkAdapterVlanCim' } -MockWith {
                    return ([PSCustomObject]@{
                        OperationMode = 'Access'
                        AccessVlanId  = 200
                    })
                }

                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Set-VMNetworkAdapterVlan' } -MockWith { }

                Repair-SdnVMNetworkAdapterPortProfile -VMName $testData.VMName -MacAddress $testData.MacAddress `
                    -NcUri $testData.NcUri -HyperVHost $testData.HyperVHost -WarningAction SilentlyContinue

                Should -Invoke -CommandName Invoke-SdnCommand -Exactly -Times 1 -ParameterFilter { $ScriptBlock.ToString() -match 'Set-VMNetworkAdapterVlan' }
                Should -Invoke -CommandName Set-SdnVMNetworkAdapterPortProfile -Exactly -Times 1
            }
        }
    }

    Context 'Local Hyper-V host' {

        It "Removes the VLAN configuration when the VM network adapter is configured with an access VLAN" {
            InModuleScope SdnDiag.Server {
                $testData = $Global:PesterOfflineTests.RepairPortProfile

                Mock Get-SdnResource -RemoveParameterType 'Resource' -MockWith { return $Global:PesterOfflineTests.RepairPortProfile.NetworkInterface }
                Mock Test-ComputerNameIsLocal { return $true }
                Mock Set-SdnVMNetworkAdapterPortProfile { }
                Mock Invoke-SdnCommand { }

                Mock Get-SdnVMNetworkAdapterPortProfile {
                    return [PSCustomObject]@{
                        VMName      = $Global:PesterOfflineTests.RepairPortProfile.VMName
                        MacAddress  = $Global:PesterOfflineTests.RepairPortProfile.MacAddress
                        ProfileId   = "{$($Global:PesterOfflineTests.RepairPortProfile.InstanceId)}"
                        ProfileData = 1
                    }
                }

                Mock Get-SdnVMNetworkAdapter {
                    return [PSCustomObject]@{
                        Name       = 'Network Adapter'
                        VMName     = $Global:PesterOfflineTests.RepairPortProfile.VMName
                        MacAddress = $Global:PesterOfflineTests.RepairPortProfile.MacAddress
                    }
                }

                # the local host code path receives the live object from Get-VMNetworkAdapterVlan, so the enum
                # is returned as-is rather than being deserialized as its underlying integer value.
                Mock Get-SdnVMNetworkAdapterVlanCim {
                    return [PSCustomObject]@{
                        OperationMode = 'Access'
                        AccessVlanId  = 101
                    }
                }

                Mock Set-VMNetworkAdapterVlan { }

                Repair-SdnVMNetworkAdapterPortProfile -VMName $testData.VMName -MacAddress $testData.MacAddress `
                    -NcUri $testData.NcUri -HyperVHost $testData.HyperVHost -WarningAction SilentlyContinue

                Should -Invoke -CommandName Set-VMNetworkAdapterVlan -Exactly -Times 1 -ParameterFilter { $Untagged -eq $true }
                Should -Invoke -CommandName Invoke-SdnCommand -Exactly -Times 0
            }
        }

        It "Does not modify the VLAN configuration when the VM network adapter is untagged" {
            InModuleScope SdnDiag.Server {
                $testData = $Global:PesterOfflineTests.RepairPortProfile

                Mock Get-SdnResource -RemoveParameterType 'Resource' -MockWith { return $Global:PesterOfflineTests.RepairPortProfile.NetworkInterface }
                Mock Test-ComputerNameIsLocal { return $true }
                Mock Set-SdnVMNetworkAdapterPortProfile { }
                Mock Invoke-SdnCommand { }

                Mock Get-SdnVMNetworkAdapterPortProfile {
                    return [PSCustomObject]@{
                        VMName      = $Global:PesterOfflineTests.RepairPortProfile.VMName
                        MacAddress  = $Global:PesterOfflineTests.RepairPortProfile.MacAddress
                        ProfileId   = "{$($Global:PesterOfflineTests.RepairPortProfile.InstanceId)}"
                        ProfileData = 1
                    }
                }

                Mock Get-SdnVMNetworkAdapter {
                    return [PSCustomObject]@{
                        Name       = 'Network Adapter'
                        VMName     = $Global:PesterOfflineTests.RepairPortProfile.VMName
                        MacAddress = $Global:PesterOfflineTests.RepairPortProfile.MacAddress
                    }
                }

                Mock Get-SdnVMNetworkAdapterVlanCim {
                    return [PSCustomObject]@{
                        OperationMode = 'Untagged'
                        AccessVlanId  = 0
                    }
                }

                Mock Set-VMNetworkAdapterVlan { }

                Repair-SdnVMNetworkAdapterPortProfile -VMName $testData.VMName -MacAddress $testData.MacAddress `
                    -NcUri $testData.NcUri -HyperVHost $testData.HyperVHost

                Should -Invoke -CommandName Set-VMNetworkAdapterVlan -Exactly -Times 0
                Should -Invoke -CommandName Set-SdnVMNetworkAdapterPortProfile -Exactly -Times 0
            }
        }
    }
}

Describe 'Server - Get-SdnVMSwitchCim' {

    It "Returns virtual switches with friendly names" {
        InModuleScope SdnDiag.Server {
            Mock Get-CimInstance {
                return @(
                    [PSCustomObject]@{
                        ElementName    = 'ConvergedSwitch'
                        Name           = 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'
                        IOVPreferred   = $false
                        Notes          = ''
                        MaxIOVOffloads = 0
                        InstallDate    = $null
                    }
                )
            }
            Mock New-SdnCimSession { }

            $result = Get-SdnVMSwitchCim
            $result | Should -Not -BeNullOrEmpty
            $result[0].Name | Should -Be 'ConvergedSwitch'
            $result[0].SwitchId | Should -Be 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'
        }
    }

    It "Filters by switch name" {
        InModuleScope SdnDiag.Server {
            Mock Get-CimInstance {
                return @(
                    [PSCustomObject]@{
                        ElementName    = 'ConvergedSwitch'
                        Name           = 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'
                        IOVPreferred   = $false
                        Notes          = ''
                        MaxIOVOffloads = 0
                        InstallDate    = $null
                    }
                )
            }
            Mock New-SdnCimSession { }

            $result = Get-SdnVMSwitchCim -Name 'ConvergedSwitch'
            $result | Should -Not -BeNullOrEmpty
            $result[0].Name | Should -Be 'ConvergedSwitch'
        }
    }

    It "Returns empty when no switches exist" {
        InModuleScope SdnDiag.Server {
            Mock Get-CimInstance { return @() }
            Mock New-SdnCimSession { }

            $result = Get-SdnVMSwitchCim
            $result | Should -BeNullOrEmpty
        }
    }
}

Describe 'Server - Get-SdnVMNetworkAdapterCim' {

    BeforeAll {
        # shared mock data for adapter tests
        $Global:PesterOfflineTests.CimMockData = @{
            SyntheticAdapter = [PSCustomObject]@{
                ElementName              = 'Network Adapter'
                Address                  = '001DD8070001'
                InstanceID               = 'Microsoft:AAAAAAAA-1111-2222-3333-444444444444\BBBBBBBB-5555-6666-7777-888888888888'
                VirtualSystemIdentifiers = @('{BBBBBBBB-5555-6666-7777-888888888888}')
                StaticMacAddress         = $true
            }
            VmSystem = [PSCustomObject]@{
                ElementName              = 'DVLAB-VM01'
                Name                     = 'AAAAAAAA-1111-2222-3333-444444444444'
                EnabledState             = 2
                Caption                  = 'Virtual Machine'
            }
            VmSettingData = [PSCustomObject]@{
                InstanceID        = 'Microsoft:AAAAAAAA-1111-2222-3333-444444444444'
                VirtualSystemType = 'Microsoft:Hyper-V:System:Realized'
                CimSystemProperties = [PSCustomObject]@{ CimInstance = 'path' }
            }
            InternalPort = [PSCustomObject]@{
                Name             = 'vEthernet (ConvergedSwitch)'
                PermanentAddress = '001DD8070099'
                DeviceID         = '{CCCCCCCC-9999-AAAA-BBBB-CCCCCCCCCCCC}'
                StatusDescriptions = @('OK')
            }
            PortAllocation = [PSCustomObject]@{
                Address      = '001DD8070001'
                Parent       = 'Msvm_SyntheticEthernetPortSettingData.InstanceID="Microsoft:AAAAAAAA-1111-2222-3333-444444444444\\BBBBBBBB-5555-6666-7777-888888888888"'
                HostResource = @('Msvm_VirtualEthernetSwitch.CreationClassName="Msvm_VirtualEthernetSwitch",Name="AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"')
                InstanceID   = 'Microsoft:AAAAAAAA-1111-2222-3333-444444444444\BBBBBBBB-5555-6666-7777-888888888888\port001'
            }
        }
    }

    It "Returns VM network adapters with VMName and SwitchName resolved" {
        InModuleScope SdnDiag.Server {
            $mockData = $Global:PesterOfflineTests.CimMockData

            Mock Get-SdnVMSwitchCim {
                return @([PSCustomObject]@{ Name = 'ConvergedSwitch'; SwitchId = 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE' })
            }
            Mock Get-CimInstance {
                switch ($ClassName) {
                    'Msvm_EthernetPortAllocationSettingData' { return @($Global:PesterOfflineTests.CimMockData.PortAllocation) }
                    'Msvm_SyntheticEthernetPortSettingData'  { return @($Global:PesterOfflineTests.CimMockData.SyntheticAdapter) }
                    'Msvm_EmulatedEthernetPortSettingData'   { return @() }
                    'Msvm_ComputerSystem'                    { return @($Global:PesterOfflineTests.CimMockData.VmSystem) }
                    'Msvm_VirtualSystemSettingData'          { return @($Global:PesterOfflineTests.CimMockData.VmSettingData) }
                    default { return @() }
                }
            }
            Mock Get-SdnCimAssociatedInstance { return $null }
            Mock New-SdnCimSession { }

            $result = Get-SdnVMNetworkAdapterCim
            $result | Should -Not -BeNullOrEmpty
            $result[0].MacAddress | Should -Be '001DD8070001'
            $result[0].VMName | Should -Be 'DVLAB-VM01'
            $result[0].SwitchName | Should -Be 'ConvergedSwitch'
            $result[0].IsManagement | Should -BeFalse
        }
    }

    It "Returns Management OS adapters when -ManagementOS is specified" {
        InModuleScope SdnDiag.Server {
            Mock Get-SdnVMSwitchCim {
                return @([PSCustomObject]@{ Name = 'ConvergedSwitch'; SwitchId = 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE' })
            }
            Mock Get-CimInstance {
                switch ($ClassName) {
                    'Msvm_EthernetPortAllocationSettingData' { return @() }
                    'Msvm_InternalEthernetPort' {
                        return @($Global:PesterOfflineTests.CimMockData.InternalPort)
                    }
                    default { return @() }
                }
            }
            Mock New-SdnCimSession { }

            $result = Get-SdnVMNetworkAdapterCim -ManagementOS
            $result | Should -Not -BeNullOrEmpty
            $result[0].IsManagement | Should -BeTrue
            $result[0].Name | Should -Be 'vEthernet (ConvergedSwitch)'
        }
    }

    It "Returns both VM and Management OS adapters when -All is specified" {
        InModuleScope SdnDiag.Server {
            $mockData = $Global:PesterOfflineTests.CimMockData

            Mock Get-SdnVMSwitchCim {
                return @([PSCustomObject]@{ Name = 'ConvergedSwitch'; SwitchId = 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE' })
            }
            Mock Get-CimInstance {
                switch ($ClassName) {
                    'Msvm_EthernetPortAllocationSettingData' { return @($Global:PesterOfflineTests.CimMockData.PortAllocation) }
                    'Msvm_InternalEthernetPort'             { return @($Global:PesterOfflineTests.CimMockData.InternalPort) }
                    'Msvm_SyntheticEthernetPortSettingData'  { return @($Global:PesterOfflineTests.CimMockData.SyntheticAdapter) }
                    'Msvm_EmulatedEthernetPortSettingData'   { return @() }
                    'Msvm_ComputerSystem'                    { return @($Global:PesterOfflineTests.CimMockData.VmSystem) }
                    'Msvm_VirtualSystemSettingData'          { return @($Global:PesterOfflineTests.CimMockData.VmSettingData) }
                    default { return @() }
                }
            }
            Mock Get-SdnCimAssociatedInstance {
                return $null
            }
            Mock New-SdnCimSession { }

            $result = Get-SdnVMNetworkAdapterCim -All
            $result | Should -Not -BeNullOrEmpty
            ($result | Where-Object { $_.IsManagement -eq $true }) | Should -Not -BeNullOrEmpty
            ($result | Where-Object { $_.IsManagement -eq $false }) | Should -Not -BeNullOrEmpty
        }
    }

    It "Filters by VMName" {
        InModuleScope SdnDiag.Server {
            Mock Get-SdnVMSwitchCim { return @() }
            Mock Get-CimInstance {
                switch ($ClassName) {
                    'Msvm_EthernetPortAllocationSettingData' { return @() }
                    'Msvm_ComputerSystem' { return @($Global:PesterOfflineTests.CimMockData.VmSystem) }
                    'Msvm_EmulatedEthernetPortSettingData'   { return @() }
                    'Msvm_VirtualSystemSettingData'          { return @($Global:PesterOfflineTests.CimMockData.VmSettingData) }
                    default { return @() }
                }
            }
            Mock Get-SdnCimAssociatedInstance {
                switch ($ResultClassName) {
                    'Msvm_VirtualSystemSettingData' { return $Global:PesterOfflineTests.CimMockData.VmSettingData }
                    'Msvm_SyntheticEthernetPortSettingData' { return @($Global:PesterOfflineTests.CimMockData.SyntheticAdapter) }
                    default { return $null }
                }
            }
            Mock New-SdnCimSession { }

            $result = Get-SdnVMNetworkAdapterCim -VMName 'DVLAB-VM01'
            $result | Should -Not -BeNullOrEmpty
            $result[0].VMName | Should -Be 'DVLAB-VM01'
        }
    }
}

Describe 'Server - Get-SdnVMCim' {

    It "Returns VMs with state mapped to friendly names" {
        InModuleScope SdnDiag.Server {
            Mock Get-CimInstance {
                return @(
                    [PSCustomObject]@{ ElementName = 'DVLAB-VM01'; Name = 'AAAAAAAA-1111-2222-3333-444444444444'; EnabledState = 2; Caption = 'Virtual Machine' },
                    [PSCustomObject]@{ ElementName = 'DVLAB-VM02'; Name = 'BBBBBBBB-1111-2222-3333-444444444444'; EnabledState = 3; Caption = 'Virtual Machine' }
                )
            }
            Mock Get-SdnCimAssociatedInstance {
                switch ($ResultClassName) {
                    'Msvm_VirtualSystemSettingData' {
                        return [PSCustomObject]@{
                            InstanceID        = "Microsoft:$($InputObject.Name)"
                            VirtualSystemType = 'Microsoft:Hyper-V:System:Realized'
                        }
                    }
                    'Msvm_SyntheticEthernetPortSettingData' { return @() }
                    default { return $null }
                }
            }
            Mock New-SdnCimSession { }

            $result = Get-SdnVMCim
            $result | Should -HaveCount 2
            $result[0].State | Should -Be 'Running'
            $result[1].State | Should -Be 'Off'
        }
    }

    It "Filters by VMName" {
        InModuleScope SdnDiag.Server {
            Mock Get-CimInstance {
                return @(
                    [PSCustomObject]@{ ElementName = 'DVLAB-VM01'; Name = 'AAAAAAAA-1111-2222-3333-444444444444'; EnabledState = 2; Caption = 'Virtual Machine' }
                )
            }
            Mock Get-SdnCimAssociatedInstance {
                switch ($ResultClassName) {
                    'Msvm_VirtualSystemSettingData' {
                        return [PSCustomObject]@{
                            InstanceID        = 'Microsoft:AAAAAAAA-1111-2222-3333-444444444444'
                            VirtualSystemType = 'Microsoft:Hyper-V:System:Realized'
                        }
                    }
                    'Msvm_SyntheticEthernetPortSettingData' { return @() }
                    default { return $null }
                }
            }
            Mock New-SdnCimSession { }

            $result = Get-SdnVMCim -VMName 'DVLAB-VM01'
            $result | Should -HaveCount 1
            $result[0].Name | Should -Be 'DVLAB-VM01'
        }
    }

    It "Returns empty when no VMs exist" {
        InModuleScope SdnDiag.Server {
            Mock Get-CimInstance { return @() }
            Mock Get-SdnCimAssociatedInstance { return $null }
            Mock New-SdnCimSession { }

            $result = Get-SdnVMCim
            $result | Should -BeNullOrEmpty
        }
    }
}

Describe 'Server - Get-SdnVMNetworkAdapterPortProfile (CIM)' {

    It "Returns port profiles with ProfileId and ProfileData" {
        InModuleScope SdnDiag.Server {
            Mock Get-CimInstance {
                switch ($ClassName) {
                    'Msvm_EthernetPortAllocationSettingData' {
                        return @(
                            [PSCustomObject]@{
                                Address    = '001DD8070001'
                                InstanceID = 'Microsoft:AAAAAAAA-1111-2222-3333-444444444444\BBBBBBBB-5555-6666-7777-888888888888'
                                ElementName = 'port001'
                            }
                        )
                    }
                    'Msvm_EthernetSwitchPortProfileSettingData' {
                        return @(
                            [PSCustomObject]@{
                                InstanceID  = 'Microsoft:AAAAAAAA-1111-2222-3333-444444444444\BBBBBBBB-5555-6666-7777-888888888888\C\PPPP0001-0000-0000-0000-000000000001'
                                ProfileId   = '{11111111-2222-3333-4444-555555555555}'
                                ProfileData = 1
                                VendorId    = '{1FA41B39-B444-4E43-B35A-E1F7985FD548}'
                            }
                        )
                    }
                    default { return @() }
                }
            }
            Mock Get-SdnVMNetworkAdapterCim {
                return @(
                    [PSCustomObject]@{
                        Name         = 'Network Adapter'
                        MacAddress   = '001DD8070001'
                        VMName       = 'DVLAB-VM01'
                        IsManagement = $false
                        InstanceID   = 'Microsoft:AAAAAAAA-1111-2222-3333-444444444444\BBBBBBBB-5555-6666-7777-888888888888'
                    }
                )
            }
            Mock New-SdnCimSession { }

            $result = Get-SdnVMNetworkAdapterPortProfile -VMName 'DVLAB-VM01'
            $result | Should -Not -BeNullOrEmpty
            $result[0].ProfileId | Should -Be '{11111111-2222-3333-4444-555555555555}'
            $result[0].ProfileData | Should -Be 1
            $result[0].MacAddress | Should -Be '001DD8070001'
        }
    }

    It "Passes -All through to Get-SdnVMNetworkAdapterCim" {
        InModuleScope SdnDiag.Server {
            Mock Get-CimInstance { return @() }
            Mock Get-SdnVMNetworkAdapterCim { return @() }
            Mock New-SdnCimSession { }

            Get-SdnVMNetworkAdapterPortProfile -All

            Should -Invoke -CommandName Get-SdnVMNetworkAdapterCim -ParameterFilter { $All -eq $true }
        }
    }
}

Describe 'Server - Get-SdnVMNetworkAdapterVlanCim' {

    It "Returns VLAN settings with OperationMode as string" {
        InModuleScope SdnDiag.Server {
            Mock Get-CimInstance {
                switch ($ClassName) {
                    'Msvm_EthernetPortAllocationSettingData' {
                        return @([PSCustomObject]@{
                            Address    = '001DD8070001'
                            InstanceID = 'Microsoft:VMGUID\PortGUID'
                        })
                    }
                    'Msvm_EthernetSwitchPortVlanSettingData' {
                        return @([PSCustomObject]@{
                            InstanceID              = 'Microsoft:VMGUID\PortGUID\C\VlanGUID'
                            OperationMode           = 1
                            AccessVlanId            = 100
                            NativeVlanId            = 0
                            PrimaryVlanId           = 0
                            SecondaryVlanId         = 0
                            SecondaryVlanIdList     = $null
                            PvlanMode               = $null
                            PruneEnabledVlanIdArray = $null
                            TrunkVlanIdArray        = $null
                        })
                    }
                    default { return @() }
                }
            }
            Mock Get-SdnVMNetworkAdapterCim {
                return @([PSCustomObject]@{
                    Name = 'Network Adapter'; MacAddress = '001DD8070001'; VMName = 'DVLAB-VM01'; IsManagement = $false
                })
            }
            Mock New-SdnCimSession { }
            Mock Format-SdnMacAddress { return $MacAddress.ToUpper() -replace '-','' }

            $result = Get-SdnVMNetworkAdapterVlanCim -VMName 'DVLAB-VM01'
            $result | Should -Not -BeNullOrEmpty
            $result[0].OperationMode | Should -Be 'Access'
            $result[0].AccessVlanId | Should -Be 100
            $result[0].VMName | Should -Be 'DVLAB-VM01'
        }
    }

    It "Returns Untagged when no VLAN setting exists for adapter" {
        InModuleScope SdnDiag.Server {
            Mock Get-CimInstance { return @() }
            Mock Get-SdnVMNetworkAdapterCim {
                return @([PSCustomObject]@{
                    Name = 'Network Adapter'; MacAddress = '001DD8070001'; VMName = 'DVLAB-VM01'; IsManagement = $false
                })
            }
            Mock New-SdnCimSession { }
            Mock Format-SdnMacAddress { return $MacAddress.ToUpper() -replace '-','' }

            $result = Get-SdnVMNetworkAdapterVlanCim -All
            $result | Should -Not -BeNullOrEmpty
            $result[0].OperationMode | Should -Be 'Untagged'
        }
    }
}

Describe 'Server - Get-SdnVMNetworkAdapterIsolationCim' {

    It "Returns isolation settings for adapters" {
        InModuleScope SdnDiag.Server {
            Mock Get-CimInstance {
                switch ($ClassName) {
                    'Msvm_EthernetPortAllocationSettingData' {
                        return @([PSCustomObject]@{ Address = '001DD8070001'; InstanceID = 'Microsoft:VMGUID\PortGUID' })
                    }
                    'Msvm_EthernetSwitchPortIsolationSettingData' {
                        return @([PSCustomObject]@{
                            InstanceID             = 'Microsoft:VMGUID\PortGUID\C\IsoGUID'
                            IsolationMode          = 1
                            DefaultIsolationId     = 4096
                            AllowUntaggedTraffic   = $true
                            EnableMultiTenantStack = $false
                        })
                    }
                    default { return @() }
                }
            }
            Mock Get-SdnVMNetworkAdapterCim {
                return @([PSCustomObject]@{
                    Name = 'Network Adapter'; MacAddress = '001DD8070001'; VMName = 'DVLAB-VM01'; IsManagement = $false
                })
            }
            Mock New-SdnCimSession { }
            Mock Format-SdnMacAddress { return $MacAddress.ToUpper() -replace '-','' }

            $result = Get-SdnVMNetworkAdapterIsolationCim -All
            $result | Should -Not -BeNullOrEmpty
            $result[0].IsolationMode | Should -Be 1
            $result[0].DefaultIsolationId | Should -Be 4096
        }
    }
}

Describe 'Server - Get-SdnVMNetworkAdapterExtendedAclCim' {

    It "Returns extended ACL entries per adapter" {
        InModuleScope SdnDiag.Server {
            Mock Get-CimInstance {
                switch ($ClassName) {
                    'Msvm_EthernetPortAllocationSettingData' {
                        return @([PSCustomObject]@{ Address = '001DD8070001'; InstanceID = 'Microsoft:VMGUID\PortGUID' })
                    }
                    'Msvm_EthernetSwitchPortExtendedAclSettingData' {
                        return @(
                            [PSCustomObject]@{
                                InstanceID         = 'Microsoft:VMGUID\PortGUID\C\AclGUID'
                                Direction          = 1
                                Action             = 1
                                LocalAddress       = '*'
                                RemoteAddress      = '10.0.0.0/8'
                                LocalPort          = '*'
                                RemotePort         = '443'
                                Protocol           = 'TCP'
                                Weight             = 100
                                IsStateful         = $true
                                IdleSessionTimeout = 0
                                IsolationID        = 0
                            }
                        )
                    }
                    default { return @() }
                }
            }
            Mock Get-SdnVMNetworkAdapterCim {
                return @([PSCustomObject]@{
                    Name = 'Network Adapter'; MacAddress = '001DD8070001'; VMName = 'DVLAB-VM01'; IsManagement = $false
                })
            }
            Mock New-SdnCimSession { }
            Mock Format-SdnMacAddress { return $MacAddress.ToUpper() -replace '-','' }

            $result = Get-SdnVMNetworkAdapterExtendedAclCim -All
            $result | Should -Not -BeNullOrEmpty
            $result[0].Direction | Should -Be 1
            $result[0].RemoteAddress | Should -Be '10.0.0.0/8'
            $result[0].Protocol | Should -Be 'TCP'
        }
    }
}

Describe 'Server - Get-SdnVMNetworkAdapterRoutingDomainCim' {

    It "Returns routing domain entries per adapter" {
        InModuleScope SdnDiag.Server {
            Mock Get-CimInstance {
                switch ($ClassName) {
                    'Msvm_EthernetPortAllocationSettingData' {
                        return @([PSCustomObject]@{ Address = '001DD8070001'; InstanceID = 'Microsoft:VMGUID\PortGUID' })
                    }
                    'Msvm_EthernetSwitchPortRoutingDomainSettingData' {
                        return @(
                            [PSCustomObject]@{
                                InstanceID          = 'Microsoft:VMGUID\PortGUID\C\RdGUID'
                                RoutingDomainGuid   = '{11111111-2222-3333-4444-555555555555}'
                                RoutingDomainName   = 'VNET-001'
                                IsolationIdList     = @(4096, 4097)
                                IsolationIdNameList = @('Subnet-1', 'Subnet-2')
                            }
                        )
                    }
                    default { return @() }
                }
            }
            Mock Get-SdnVMNetworkAdapterCim {
                return @([PSCustomObject]@{
                    Name = 'Network Adapter'; MacAddress = '001DD8070001'; VMName = 'DVLAB-VM01'; IsManagement = $false
                })
            }
            Mock New-SdnCimSession { }
            Mock Format-SdnMacAddress { return $MacAddress.ToUpper() -replace '-','' }

            $result = Get-SdnVMNetworkAdapterRoutingDomainCim -All
            $result | Should -Not -BeNullOrEmpty
            $result[0].RoutingDomainName | Should -Be 'VNET-001'
            $result[0].IsolationIdList | Should -Contain 4096
        }
    }
}
