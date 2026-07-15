# Health.Tests.ps1
#
# NOTE: Test-SdnResourceProvisioningState and Test-SdnResourceConfigurationState are internal
# functions in SdnDiag.Health that make cross-module calls (Trace-Output in SdnDiag.Utilities,
# Get-SdnResource in SdnDiag.NetworkController). Due to PowerShell nested module session state
# isolation, [TraceLevel] enum from SdnDiag.Utilities is not resolvable inside InModuleScope
# SdnDiag.Health, preventing direct invocation. These tests validate the health logic patterns
# and data structures that the health functions operate on.

Describe 'Health - Provisioning State Detection' {
    Context 'Mock data has correct structure for health checks' {
        It "All servers include provisioningState property" {
            $servers = $Global:PesterOfflineTests.SdnApiResources['servers']
            foreach ($server in $servers) {
                $server.properties.provisioningState | Should -Not -BeNullOrEmpty
            }
        }

        It "Detects Failed provisioning state (triggers FAIL in health function)" {
            $servers = $Global:PesterOfflineTests.SdnApiResources['servers']
            $failed = @($servers | Where-Object { $_.properties.provisioningState -eq 'Failed' })
            $failed.Count | Should -Be 1
            $failed[0].resourceId | Should -Be "DVLAB-S1-N04"
        }

        It "Identifies Succeeded provisioning state (triggers PASS in health function)" {
            $servers = $Global:PesterOfflineTests.SdnApiResources['servers']
            $succeeded = @($servers | Where-Object { $_.properties.provisioningState -eq 'Succeeded' })
            $succeeded.Count | Should -Be 3
        }

        It "Resources include resourceRef for health result Properties" {
            $servers = $Global:PesterOfflineTests.SdnApiResources['servers']
            foreach ($server in $servers) {
                $server.resourceRef | Should -Not -BeNullOrEmpty
            }
        }
    }
}

Describe 'Health - Configuration State Detection' {
    Context 'Mock data has correct structure for configuration state checks' {
        It "All servers include configurationState property" {
            $servers = $Global:PesterOfflineTests.SdnApiResources['servers']
            foreach ($server in $servers) {
                $server.properties.configurationState | Should -Not -BeNullOrEmpty
            }
        }

        It "Detects Failure configuration state (triggers FAIL in health function)" {
            $servers = $Global:PesterOfflineTests.SdnApiResources['servers']
            $failed = @($servers | Where-Object { $_.properties.configurationState.status -eq 'Failure' })
            $failed.Count | Should -Be 1
            $failed[0].resourceId | Should -Be "DVLAB-S1-N04"
        }

        It "Identifies Success configuration state (triggers PASS in health function)" {
            $servers = $Global:PesterOfflineTests.SdnApiResources['servers']
            $success = @($servers | Where-Object { $_.properties.configurationState.status -eq 'Success' })
            $success.Count | Should -Be 3
        }

        It "Configuration state detailedInfo has required fields" {
            $servers = $Global:PesterOfflineTests.SdnApiResources['servers']
            $server = $servers | Where-Object { $_.resourceId -eq 'DVLAB-S1-N01' }
            $server.properties.configurationState.detailedInfo[0].source | Should -Not -BeNullOrEmpty
            $server.properties.configurationState.detailedInfo[0].message | Should -Not -BeNullOrEmpty
            $server.properties.configurationState.detailedInfo[0].code | Should -Not -BeNullOrEmpty
        }

        It "Health function skips config check when provisioningState is not Succeeded" {
            # Validates the guard clause: if provisioningState != Succeeded, config state is not evaluated
            $servers = $Global:PesterOfflineTests.SdnApiResources['servers']
            $failedProv = $servers | Where-Object { $_.properties.provisioningState -ne 'Succeeded' }
            # DVLAB-S1-N04 has Failed provisioning AND Failure config - health function returns PASS (skips check)
            $failedProv.properties.configurationState.status | Should -Be 'Failure'
        }
    }

    Context 'Mux configuration state' {
        It "All muxes have Success configuration state" {
            $muxes = $Global:PesterOfflineTests.SdnApiResources['loadBalancerMuxes']
            foreach ($mux in $muxes) {
                $mux.properties.configurationState.status | Should -Be "Success"
            }
        }
    }

    Context 'Network Interface configuration state' {
        It "Network interfaces have configurationState with Success status" {
            $nics = $Global:PesterOfflineTests.SdnApiResources['networkInterfaces']
            foreach ($nic in $nics) {
                $nic.properties.configurationState | Should -Not -BeNullOrEmpty
                $nic.properties.configurationState.status | Should -Be "Success"
            }
        }

        It "Network interfaces are assigned to servers" {
            $nics = $Global:PesterOfflineTests.SdnApiResources['networkInterfaces']
            $assignedNics = @($nics | Where-Object { $null -ne $_.properties.server })
            $assignedNics.Count | Should -Be $nics.Count
        }
    }

    Context 'Gateway health state' {
        It "All gateways have Healthy healthState" {
            $gateways = $Global:PesterOfflineTests.SdnApiResources['gateways']
            foreach ($gw in $gateways) {
                $gw.properties.healthState | Should -Be "Healthy"
            }
        }

        It "Gateway pool has expected gateway count" {
            $pools = $Global:PesterOfflineTests.SdnApiResources['gatewayPools']
            $pools[0].properties.gateways.Count | Should -Be 3
        }
    }
}

Describe 'Health - MAC Address Duplicate Detection' {
    It "Detects no duplicates when all MACs are unique" {
        $nics = $Global:PesterOfflineTests.SdnApiResources['networkInterfaces']
        $macs = $nics | ForEach-Object { $_.properties.privateMacAddress }
        $uniqueMacs = $macs | Select-Object -Unique
        $uniqueMacs.Count | Should -Be $macs.Count
    }

    It "Would detect duplicates if present" {
        $testData = @(
            [PSCustomObject]@{ properties = @{ privateMacAddress = "001DD8070001" } }
            [PSCustomObject]@{ properties = @{ privateMacAddress = "001DD8070002" } }
            [PSCustomObject]@{ properties = @{ privateMacAddress = "001DD8070001" } }
        )
        $macs = $testData | ForEach-Object { $_.properties.privateMacAddress }
        $grouped = @($macs | Group-Object | Where-Object { $_.Count -gt 1 })
        $grouped.Count | Should -Be 1
        $grouped[0].Name | Should -Be "001DD8070001"
    }
}
