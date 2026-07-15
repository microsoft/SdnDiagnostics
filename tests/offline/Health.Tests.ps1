Describe 'Health - Resource State Validation' {
    BeforeAll {
        Mock -ModuleName SdnDiagnostics Get-SdnResource {
            if (![string]::IsNullOrEmpty($ResourceRef)) {
                return $Global:PesterOfflineTests.SdnApiResourcesByRef[$ResourceRef]
            }
            else {
                return $Global:PesterOfflineTests.SdnApiResources[$ResourceType.ToString()]
            }
        }
    }

    Context 'Provisioning State checks' {
        It "All servers include provisioningState property" {
            $servers = $Global:PesterOfflineTests.SdnApiResources['servers']
            foreach ($server in $servers) {
                $server.properties.provisioningState | Should -Not -BeNullOrEmpty
            }
        }

        It "Detects servers with Failed provisioning state" {
            $servers = $Global:PesterOfflineTests.SdnApiResources['servers']
            $failed = $servers | Where-Object { $_.properties.provisioningState -ne 'Succeeded' }
            $failed.Count | Should -Be 1
            $failed[0].resourceId | Should -Be "DVLAB-S1-N04"
        }

        It "Identifies servers with Succeeded provisioning state" {
            $servers = $Global:PesterOfflineTests.SdnApiResources['servers']
            $succeeded = $servers | Where-Object { $_.properties.provisioningState -eq 'Succeeded' }
            $succeeded.Count | Should -Be 3
        }
    }

    Context 'Configuration State checks' {
        It "All servers include configurationState property" {
            $servers = $Global:PesterOfflineTests.SdnApiResources['servers']
            foreach ($server in $servers) {
                $server.properties.configurationState | Should -Not -BeNullOrEmpty
            }
        }

        It "Detects servers with Failure configuration state" {
            $servers = $Global:PesterOfflineTests.SdnApiResources['servers']
            $failed = $servers | Where-Object { $_.properties.configurationState.status -eq 'Failure' }
            $failed.Count | Should -Be 1
            $failed[0].resourceId | Should -Be "DVLAB-S1-N04"
        }

        It "Identifies servers with Success configuration state" {
            $servers = $Global:PesterOfflineTests.SdnApiResources['servers']
            $success = $servers | Where-Object { $_.properties.configurationState.status -eq 'Success' }
            $success.Count | Should -Be 3
        }

        It "All muxes have Success configuration state" {
            $muxes = $Global:PesterOfflineTests.SdnApiResources['loadBalancerMuxes']
            foreach ($mux in $muxes) {
                $mux.properties.configurationState.status | Should -Be "Success"
            }
        }

        It "Configuration state detailedInfo contains source and message" {
            $servers = $Global:PesterOfflineTests.SdnApiResources['servers']
            $server = $servers | Where-Object { $_.resourceId -eq 'DVLAB-S1-N01' }
            $server.properties.configurationState.detailedInfo[0].source | Should -Not -BeNullOrEmpty
            $server.properties.configurationState.detailedInfo[0].message | Should -Not -BeNullOrEmpty
            $server.properties.configurationState.detailedInfo[0].code | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Network Interface Health' {
        It "Network interfaces have configurationState" {
            $nics = $Global:PesterOfflineTests.SdnApiResources['networkInterfaces']
            foreach ($nic in $nics) {
                $nic.properties.configurationState | Should -Not -BeNullOrEmpty
                $nic.properties.configurationState.status | Should -Be "Success"
            }
        }

        It "Network interfaces are assigned to servers" {
            $nics = $Global:PesterOfflineTests.SdnApiResources['networkInterfaces']
            $assignedNics = $nics | Where-Object { $null -ne $_.properties.server }
            $assignedNics.Count | Should -Be $nics.Count
        }
    }

    Context 'Gateway Health' {
        It "All gateways have healthState property" {
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
        # Simulate duplicate MACs
        $testData = @(
            [PSCustomObject]@{ properties = @{ privateMacAddress = "001DD8070001" } }
            [PSCustomObject]@{ properties = @{ privateMacAddress = "001DD8070002" } }
            [PSCustomObject]@{ properties = @{ privateMacAddress = "001DD8070001" } }
        )
        $macs = $testData | ForEach-Object { $_.properties.privateMacAddress }
        $grouped = $macs | Group-Object | Where-Object { $_.Count -gt 1 }
        $grouped.Count | Should -Be 1
        $grouped[0].Name | Should -Be "001DD8070001"
    }
}
