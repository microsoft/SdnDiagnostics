# Health.Tests.ps1
#
# Tests exercise the actual health validation functions in SdnDiag.Health
# (Test-SdnResourceProvisioningState and Test-SdnResourceConfigurationState)
# through InModuleScope SdnDiag.Health with a mocked Get-SdnResource, so
# regressions in the health logic are caught by CI.

Describe 'Health - Test-SdnResourceProvisioningState' {
    It "Returns FAIL when resource has Failed provisioning state" {
        InModuleScope SdnDiag.Health {
            Mock Get-SdnResource {
                return $Global:PesterOfflineTests.SdnApiResourcesByRef['/servers/DVLAB-S1-N04']
            }
            $result = Test-SdnResourceProvisioningState -Resource 'Servers' -ResourceId 'DVLAB-S1-N04' -NcUri 'https://dvlab-nc.dvlab.contoso.local'
            $result.Result | Should -Be 'FAIL'
        }
    }

    It "Returns PASS when resource has Succeeded provisioning state" {
        InModuleScope SdnDiag.Health {
            Mock Get-SdnResource {
                return $Global:PesterOfflineTests.SdnApiResourcesByRef['/servers/DVLAB-S1-N01']
            }
            $result = Test-SdnResourceProvisioningState -Resource 'Servers' -ResourceId 'DVLAB-S1-N01' -NcUri 'https://dvlab-nc.dvlab.contoso.local'
            $result.Result | Should -Be 'PASS'
        }
    }
}

Describe 'Health - Test-SdnResourceConfigurationState' {
    It "Returns PASS when provisioningState is not Succeeded (guard clause skips config check)" {
        InModuleScope SdnDiag.Health {
            # DVLAB-S1-N04 has provisioningState: Failed, so config state check is skipped
            Mock Get-SdnResource {
                return $Global:PesterOfflineTests.SdnApiResourcesByRef['/servers/DVLAB-S1-N04']
            }
            $result = Test-SdnResourceConfigurationState -Resource 'Servers' -ResourceId 'DVLAB-S1-N04' -NcUri 'https://dvlab-nc.dvlab.contoso.local'
            $result.Result | Should -Be 'PASS'
        }
    }

    It "Returns PASS when resource has Success configuration state" {
        InModuleScope SdnDiag.Health {
            Mock Get-SdnResource {
                return $Global:PesterOfflineTests.SdnApiResourcesByRef['/servers/DVLAB-S1-N01']
            }
            $result = Test-SdnResourceConfigurationState -Resource 'Servers' -ResourceId 'DVLAB-S1-N01' -NcUri 'https://dvlab-nc.dvlab.contoso.local'
            $result.Result | Should -Be 'PASS'
        }
    }

    It "Returns FAIL when resource has Failure configuration state" {
        InModuleScope SdnDiag.Health {
            Mock Get-SdnResource {
                return [PSCustomObject]@{
                    resourceRef = '/servers/test-failed-config'
                    resourceId  = 'test-failed-config'
                    properties  = [PSCustomObject]@{
                        provisioningState  = 'Succeeded'
                        configurationState = [PSCustomObject]@{
                            status      = 'Failure'
                            detailedInfo = @(
                                [PSCustomObject]@{
                                    code    = 'HostUnreachable'
                                    source  = 'SoftwareLoadBalancerManager'
                                    message = 'Host is unreachable.'
                                }
                            )
                        }
                    }
                }
            }
            $result = Test-SdnResourceConfigurationState -Resource 'Servers' -ResourceId 'test-failed-config' -NcUri 'https://dvlab-nc.dvlab.contoso.local'
            $result.Result | Should -Be 'FAIL'
        }
    }

    It "Returns WARNING when resource has Warning configuration state" {
        InModuleScope SdnDiag.Health {
            Mock Get-SdnResource {
                return [PSCustomObject]@{
                    resourceRef = '/servers/test-warning-config'
                    resourceId  = 'test-warning-config'
                    properties  = [PSCustomObject]@{
                        provisioningState  = 'Succeeded'
                        configurationState = [PSCustomObject]@{
                            status      = 'Warning'
                            detailedInfo = @()
                        }
                    }
                }
            }
            $result = Test-SdnResourceConfigurationState -Resource 'Servers' -ResourceId 'test-warning-config' -NcUri 'https://dvlab-nc.dvlab.contoso.local'
            $result.Result | Should -Be 'WARNING'
        }
    }
}
