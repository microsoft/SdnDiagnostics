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

                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Get-VMNetworkAdapterVlan' } -MockWith {
                    return ([PSCustomObject]@{
                        OperationMode = [SdnDiagnostics.PesterOffline.VMNetworkAdapterVlanMode]::Access
                        AccessVlanId  = 101
                    } | ConvertTo-PesterRemoteObject)
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
                    return ([PSCustomObject]@{
                        OperationMode           = [SdnDiagnostics.PesterOffline.VMNetworkAdapterVlanMode]::Trunk
                        NativeVlanId            = 0
                        AllowedVlanIdList       = @(1..100)
                        AllowedVlanIdListString = '1-100'
                    } | ConvertTo-PesterRemoteObject)
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
                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Get-VMNetworkAdapterVlan' } -MockWith {
                    return ([PSCustomObject]@{
                        OperationMode             = [SdnDiagnostics.PesterOffline.VMNetworkAdapterVlanMode]::Private
                        PrivateVlanMode           = [SdnDiagnostics.PesterOffline.VMNetworkAdapterPrivateVlanMode]::Promiscuous
                        PrimaryVlanId             = 10
                        SecondaryVlanId           = 0
                        SecondaryVlanIdList       = @(11, 12)
                        SecondaryVlanIdListString = '11-12'
                    } | ConvertTo-PesterRemoteObject)
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
                Mock Invoke-SdnCommand -ParameterFilter { $ScriptBlock.ToString() -match 'Get-VMNetworkAdapterVlan' } -MockWith {
                    return ([PSCustomObject]@{
                        OperationMode             = [SdnDiagnostics.PesterOffline.VMNetworkAdapterVlanMode]::Private
                        PrivateVlanMode           = [SdnDiagnostics.PesterOffline.VMNetworkAdapterPrivateVlanMode]::Isolated
                        PrimaryVlanId             = 10
                        SecondaryVlanId           = 11
                        SecondaryVlanIdList       = $null
                        SecondaryVlanIdListString = $null
                    } | ConvertTo-PesterRemoteObject)
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
                    return ([PSCustomObject]@{
                        OperationMode = [SdnDiagnostics.PesterOffline.VMNetworkAdapterVlanMode]::Untagged
                        AccessVlanId  = 0
                    } | ConvertTo-PesterRemoteObject)
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
                    return ([PSCustomObject]@{
                        OperationMode = [SdnDiagnostics.PesterOffline.VMNetworkAdapterVlanMode]::Untagged
                        AccessVlanId  = 0
                    } | ConvertTo-PesterRemoteObject)
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
                    return ([PSCustomObject]@{
                        OperationMode = [SdnDiagnostics.PesterOffline.VMNetworkAdapterVlanMode]::Access
                        AccessVlanId  = 200
                    } | ConvertTo-PesterRemoteObject)
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
                Mock Get-VMNetworkAdapterVlan {
                    return [PSCustomObject]@{
                        OperationMode = [SdnDiagnostics.PesterOffline.VMNetworkAdapterVlanMode]::Access
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
                        OperationMode = [SdnDiagnostics.PesterOffline.VMNetworkAdapterVlanMode]::Untagged
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
