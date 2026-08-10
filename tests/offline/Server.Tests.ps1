Describe 'Server - Repair-SdnVMNetworkAdapterPortProfile' {

    BeforeAll {
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

                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Get-VMNetworkAdapterVlan' } -MockWith {
                    return [PSCustomObject]@{
                        OperationMode = 'Access'
                        AccessVlanId  = 101
                    }
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

                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Get-VMNetworkAdapterVlan' } -MockWith {
                    return [PSCustomObject]@{
                        OperationMode     = 'Trunk'
                        NativeVlanId      = 0
                        AllowedVlanIdList = '1-100'
                    }
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

                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Get-VMNetworkAdapterVlan' } -MockWith {
                    return [PSCustomObject]@{
                        OperationMode = 'Untagged'
                        AccessVlanId  = 0
                    }
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

                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Get-VMNetworkAdapterVlan' } -MockWith {
                    return [PSCustomObject]@{
                        OperationMode = 'Untagged'
                        AccessVlanId  = 0
                    }
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

                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Get-VMNetworkAdapterVlan' } -MockWith {
                    return [PSCustomObject]@{
                        OperationMode = 'Access'
                        AccessVlanId  = 200
                    }
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

                Mock Get-VMNetworkAdapterVlan {
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

                Mock Get-VMNetworkAdapterVlan {
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
