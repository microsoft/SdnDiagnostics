# Health.Tests.ps1
#
# These tests exercise the production health functions in SdnDiag.Health directly rather than
# re-implementing their logic against the fixtures.
#
# - Test-SdnResourceProvisioningState / Test-SdnResourceConfigurationState call Get-SdnResource
#   (SdnDiag.NetworkController). We mock the REST layer (Invoke-RestMethodWithRetry) inside
#   SdnDiag.NetworkController so the real Get-SdnResource and health evaluation logic run against
#   controlled resource fixtures.
# - Test-VfpDuplicateMacAddress / Test-VMNetAdapterDuplicateMacAddress are invoked inside
#   InModuleScope SdnDiag.Health with their server-side data providers (Get-SdnVfpVmSwitchPort /
#   Get-SdnVMNetworkAdapter) and Confirm-IsServer mocked.

Describe 'Health - Test-SdnResourceProvisioningState' {
    It "Returns PASS with resource details when provisioningState is Succeeded" {
        Mock -ModuleName SdnDiag.NetworkController Invoke-RestMethodWithRetry {
            [PSCustomObject]@{ resourceRef = '/servers/DVLAB-S1-N01'; properties = [PSCustomObject]@{ provisioningState = 'Succeeded' } }
        }
        InModuleScope SdnDiag.Health {
            $result = Test-SdnResourceProvisioningState -Resource Servers -ResourceId 'DVLAB-S1-N01' -NcUri 'https://dvlab-nc.dvlab.contoso.local'
            $result.Result | Should -Be 'PASS'
            $result.Properties.provisioningState | Should -Be 'Succeeded'
            $result.Properties.resourceRef | Should -Be '/servers/DVLAB-S1-N01'
            $result.Remediation | Should -BeNullOrEmpty
        }
    }

    It "Returns FAIL with remediation when provisioningState is Failed" {
        Mock -ModuleName SdnDiag.NetworkController Invoke-RestMethodWithRetry {
            [PSCustomObject]@{ resourceRef = '/servers/DVLAB-S1-N04'; properties = [PSCustomObject]@{ provisioningState = 'Failed' } }
        }
        InModuleScope SdnDiag.Health {
            $result = Test-SdnResourceProvisioningState -Resource Servers -ResourceId 'DVLAB-S1-N04' -NcUri 'https://dvlab-nc.dvlab.contoso.local'
            $result.Result | Should -Be 'FAIL'
            $result.Properties.provisioningState | Should -Be 'Failed'
            $result.Remediation | Should -Not -BeNullOrEmpty
            ($result.Remediation -join '') | Should -BeLike '*DVLAB-S1-N04*'
        }
    }

    It "Returns WARNING with remediation when provisioningState is Updating" {
        Mock -ModuleName SdnDiag.NetworkController Invoke-RestMethodWithRetry {
            [PSCustomObject]@{ resourceRef = '/servers/DVLAB-S1-N02'; properties = [PSCustomObject]@{ provisioningState = 'Updating' } }
        }
        InModuleScope SdnDiag.Health {
            $result = Test-SdnResourceProvisioningState -Resource Servers -ResourceId 'DVLAB-S1-N02' -NcUri 'https://dvlab-nc.dvlab.contoso.local'
            $result.Result | Should -Be 'WARNING'
            $result.Remediation | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Health - Test-SdnResourceConfigurationState' {
    It "Returns PASS when configurationState status is Success" {
        Mock -ModuleName SdnDiag.NetworkController Invoke-RestMethodWithRetry {
            [PSCustomObject]@{
                resourceRef = '/servers/DVLAB-S1-N01'
                properties  = [PSCustomObject]@{
                    provisioningState  = 'Succeeded'
                    configurationState = [PSCustomObject]@{
                        status       = 'Success'
                        detailedInfo = @([PSCustomObject]@{ code = 'Success'; message = 'ok'; source = 'server' })
                    }
                }
            }
        }
        InModuleScope SdnDiag.Health {
            $result = Test-SdnResourceConfigurationState -Resource Servers -ResourceId 'DVLAB-S1-N01' -NcUri 'https://dvlab-nc.dvlab.contoso.local'
            $result.Result | Should -Be 'PASS'
            $result.Properties.resourceRef | Should -Be '/servers/DVLAB-S1-N01'
            $result.Remediation | Should -BeNullOrEmpty
        }
    }

    It "Returns FAIL with remediation when configurationState status is Failure" {
        Mock -ModuleName SdnDiag.NetworkController Invoke-RestMethodWithRetry {
            [PSCustomObject]@{
                resourceRef = '/servers/DVLAB-S1-N04'
                properties  = [PSCustomObject]@{
                    provisioningState  = 'Succeeded'
                    configurationState = [PSCustomObject]@{
                        status       = 'Failure'
                        detailedInfo = @([PSCustomObject]@{ code = 'PolicyConfigurationFailure'; message = 'policy failed'; source = 'server' })
                    }
                }
            }
        }
        InModuleScope SdnDiag.Health {
            $result = Test-SdnResourceConfigurationState -Resource Servers -ResourceId 'DVLAB-S1-N04' -NcUri 'https://dvlab-nc.dvlab.contoso.local'
            $result.Result | Should -Be 'FAIL'
            $result.Properties.configurationState.status | Should -Be 'Failure'
            $result.Remediation | Should -Not -BeNullOrEmpty
        }
    }

    It "Returns WARNING when configurationState status is Warning" {
        Mock -ModuleName SdnDiag.NetworkController Invoke-RestMethodWithRetry {
            [PSCustomObject]@{
                resourceRef = '/servers/DVLAB-S1-N03'
                properties  = [PSCustomObject]@{
                    provisioningState  = 'Succeeded'
                    configurationState = [PSCustomObject]@{ status = 'Warning'; detailedInfo = @() }
                }
            }
        }
        InModuleScope SdnDiag.Health {
            $result = Test-SdnResourceConfigurationState -Resource Servers -ResourceId 'DVLAB-S1-N03' -NcUri 'https://dvlab-nc.dvlab.contoso.local'
            $result.Result | Should -Be 'WARNING'
        }
    }

    It "Skips configuration check (returns PASS) when provisioningState is not Succeeded" {
        Mock -ModuleName SdnDiag.NetworkController Invoke-RestMethodWithRetry {
            [PSCustomObject]@{
                resourceRef = '/servers/DVLAB-S1-N04'
                properties  = [PSCustomObject]@{
                    provisioningState  = 'Failed'
                    configurationState = [PSCustomObject]@{ status = 'Failure'; detailedInfo = @() }
                }
            }
        }
        InModuleScope SdnDiag.Health {
            $result = Test-SdnResourceConfigurationState -Resource Servers -ResourceId 'DVLAB-S1-N04' -NcUri 'https://dvlab-nc.dvlab.contoso.local'
            # configuration state is not evaluated when provisioningState is not Succeeded
            $result.Result | Should -Be 'PASS'
            $result.Remediation | Should -BeNullOrEmpty
        }
    }
}

Describe 'Health - Test-VfpDuplicateMacAddress' {
    It "Returns FAIL and reports the duplicate MAC when VFP ports share a MAC address" {
        InModuleScope SdnDiag.Health {
            Mock Confirm-IsServer {}
            Mock Get-SdnVfpVmSwitchPort {
                @(
                    [PSCustomObject]@{ MacAddress = '00-11-22-33-44-55'; PortName = 'Port1'; PortState = 'Active'; NicName = 'Nic1'; VMName = 'VM1' }
                    [PSCustomObject]@{ MacAddress = '00-11-22-33-44-55'; PortName = 'Port2'; PortState = 'Active'; NicName = 'Nic2'; VMName = 'VM2' }
                    [PSCustomObject]@{ MacAddress = 'AA-BB-CC-DD-EE-FF'; PortName = 'Port3'; PortState = 'Active'; NicName = 'Nic3'; VMName = 'VM3' }
                )
            }
            $result = Test-VfpDuplicateMacAddress
            $result.Result | Should -Be 'FAIL'
            @($result.Properties).Count | Should -Be 2
            ($result.Remediation -join '') | Should -BeLike '*00-11-22-33-44-55*'
        }
    }

    It "Returns PASS when all VFP MAC addresses are unique" {
        InModuleScope SdnDiag.Health {
            Mock Confirm-IsServer {}
            Mock Get-SdnVfpVmSwitchPort {
                @(
                    [PSCustomObject]@{ MacAddress = '00-11-22-33-44-55'; PortName = 'Port1'; PortState = 'Active'; NicName = 'Nic1'; VMName = 'VM1' }
                    [PSCustomObject]@{ MacAddress = 'AA-BB-CC-DD-EE-FF'; PortName = 'Port2'; PortState = 'Active'; NicName = 'Nic2'; VMName = 'VM2' }
                )
            }
            $result = Test-VfpDuplicateMacAddress
            $result.Result | Should -Be 'PASS'
            $result.Remediation | Should -BeNullOrEmpty
        }
    }

    It "Excludes null and zero MAC addresses from duplicate detection" {
        InModuleScope SdnDiag.Health {
            Mock Confirm-IsServer {}
            Mock Get-SdnVfpVmSwitchPort {
                @(
                    [PSCustomObject]@{ MacAddress = '00-00-00-00-00-00'; PortName = 'Port1'; PortState = 'Active'; NicName = 'Nic1'; VMName = 'VM1' }
                    [PSCustomObject]@{ MacAddress = '00-00-00-00-00-00'; PortName = 'Port2'; PortState = 'Active'; NicName = 'Nic2'; VMName = 'VM2' }
                    [PSCustomObject]@{ MacAddress = $null; PortName = 'Port3'; PortState = 'Active'; NicName = 'Nic3'; VMName = 'VM3' }
                    [PSCustomObject]@{ MacAddress = $null; PortName = 'Port4'; PortState = 'Active'; NicName = 'Nic4'; VMName = 'VM4' }
                    [PSCustomObject]@{ MacAddress = 'AA-BB-CC-DD-EE-FF'; PortName = 'Port5'; PortState = 'Active'; NicName = 'Nic5'; VMName = 'VM5' }
                )
            }
            $result = Test-VfpDuplicateMacAddress
            $result.Result | Should -Be 'PASS'
        }
    }
}

Describe 'Health - Test-VMNetAdapterDuplicateMacAddress' {
    It "Returns FAIL and reports the duplicate MAC when VM network adapters share a MAC address" {
        InModuleScope SdnDiag.Health {
            Mock Confirm-IsServer {}
            Mock Get-SdnVMNetworkAdapter {
                @(
                    [PSCustomObject]@{ MacAddress = '001122334455'; VMName = 'VM1'; Name = 'NetAdapter1'; Status = 'Ok' }
                    [PSCustomObject]@{ MacAddress = '001122334455'; VMName = 'VM2'; Name = 'NetAdapter2'; Status = 'Ok' }
                    [PSCustomObject]@{ MacAddress = 'AABBCCDDEEFF'; VMName = 'VM3'; Name = 'NetAdapter3'; Status = 'Ok' }
                )
            }
            $result = Test-VMNetAdapterDuplicateMacAddress
            $result.Result | Should -Be 'FAIL'
            @($result.Properties).Count | Should -Be 2
            ($result.Remediation -join '') | Should -BeLike '*001122334455*'
        }
    }

    It "Returns PASS when all VM network adapter MAC addresses are unique" {
        InModuleScope SdnDiag.Health {
            Mock Confirm-IsServer {}
            Mock Get-SdnVMNetworkAdapter {
                @(
                    [PSCustomObject]@{ MacAddress = '001122334455'; VMName = 'VM1'; Name = 'NetAdapter1'; Status = 'Ok' }
                    [PSCustomObject]@{ MacAddress = 'AABBCCDDEEFF'; VMName = 'VM2'; Name = 'NetAdapter2'; Status = 'Ok' }
                )
            }
            $result = Test-VMNetAdapterDuplicateMacAddress
            $result.Result | Should -Be 'PASS'
            $result.Remediation | Should -BeNullOrEmpty
        }
    }
}
