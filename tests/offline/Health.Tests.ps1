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
            $result = Test-SdnResourceProvisioningState -Resource Servers -ResourceId 'DVLAB-S1-N04' -NcUri 'https://dvlab-nc.dvlab.contoso.local' -ErrorVariable testErrors
            $result.Result | Should -Be 'FAIL'
            $result.Properties.provisioningState | Should -Be 'Failed'
            $result.Remediation | Should -Not -BeNullOrEmpty
            ($result.Remediation -join '') | Should -BeLike '*DVLAB-S1-N04*'
            $testErrors | Should -BeNullOrEmpty
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

Describe 'Health - Test-SdnCertificateMultiple' {
    It "Keeps the most recently issued certificate instead of the certificate that expires last" {
        InModuleScope SdnDiag.Health {
            $originalRole = $Global:SdnDiagnostics.Config.Role
            $Global:SdnDiagnostics.Config.Role = 'Server'

            try {
                Mock Get-SdnServerCertificate {
                    @(
                        [PSCustomObject]@{
                            Thumbprint  = 'OLDER-ISSUED'
                            Subject     = 'CN=DVLAB-SDN'
                            FriendlyName = 'Older issued'
                            Issuer      = 'CN=DVLAB-CA'
                            NotBefore   = [datetime]'2025-01-01'
                            NotAfter    = [datetime]'2028-01-01'
                        }

                        [PSCustomObject]@{
                            Thumbprint  = 'NEWER-ISSUED'
                            Subject     = 'CN=DVLAB-SDN'
                            FriendlyName = 'Newer issued'
                            Issuer      = 'CN=DVLAB-CA'
                            NotBefore   = [datetime]'2026-01-01'
                            NotAfter    = [datetime]'2027-01-01'
                        }
                    )
                }

                $result = Test-SdnCertificateMultiple

                $result.Result | Should -Be 'WARNING'
                @($result.Properties).Count | Should -Be 1
                $result.Properties.Thumbprint | Should -Be 'OLDER-ISSUED'
            }
            finally {
                $Global:SdnDiagnostics.Config.Role = $originalRole
            }
        }
    }

    It "Keeps the most recently issued Azure Stack certificate when that issuer is present" {
        InModuleScope SdnDiag.Health {
            $originalRole = $Global:SdnDiagnostics.Config.Role
            $Global:SdnDiagnostics.Config.Role = 'Server'

            try {
                Mock Get-SdnServerCertificate {
                    @(
                        [PSCustomObject]@{
                            Thumbprint  = 'OLDER-AZURE-STACK'
                            Subject     = 'CN=DVLAB-SDN'
                            FriendlyName = 'Older Azure Stack'
                            Issuer      = 'CN=AzureStackCertificationAuthority'
                            NotBefore   = [datetime]'2025-01-01'
                            NotAfter    = [datetime]'2028-01-01'
                        }
                        [PSCustomObject]@{
                            Thumbprint  = 'NEWER-AZURE-STACK'
                            Subject     = 'CN=DVLAB-SDN'
                            FriendlyName = 'Newer Azure Stack'
                            Issuer      = 'CN=AzureStackCertificationAuthority'
                            NotBefore   = [datetime]'2026-01-01'
                            NotAfter    = [datetime]'2027-01-01'
                        }
                        [PSCustomObject]@{
                            Thumbprint  = 'NEWEST-OTHER-ISSUER'
                            Subject     = 'CN=DVLAB-SDN'
                            FriendlyName = 'Newest other issuer'
                            Issuer      = 'CN=DVLAB-CA'
                            NotBefore   = [datetime]'2026-06-01'
                            NotAfter    = [datetime]'2029-01-01'
                        }
                    )
                }

                $result = Test-SdnCertificateMultiple

                $result.Result | Should -Be 'WARNING'
                @($result.Properties.Thumbprint) | Should -Contain 'OLDER-AZURE-STACK'
                @($result.Properties.Thumbprint) | Should -Contain 'NEWEST-OTHER-ISSUER'
                @($result.Properties.Thumbprint) | Should -Not -Contain 'NEWER-AZURE-STACK'
            }
            finally {
                $Global:SdnDiagnostics.Config.Role = $originalRole
            }
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
}

Describe 'Health - Gateway peer next-hop ARP' {
        It "Selects the longest matching IPv4 route without depending on input order" {
            InModuleScope SdnDiag.Health {
                $routes = @(
                    [PSCustomObject]@{ DestinationPrefix = '0.0.0.0/0'; NextHop = '192.0.2.1'; InterfaceIndex = 10; CompartmentId = 4; RouteMetric = 1; State = 'Alive' }
                    [PSCustomObject]@{ DestinationPrefix = '10.20.30.0/24'; NextHop = '192.0.2.2'; InterfaceIndex = 11; CompartmentId = 4; RouteMetric = 50; State = 'Alive' }
                    [PSCustomObject]@{ DestinationPrefix = '10.20.30.44/32'; NextHop = '192.0.2.3'; InterfaceIndex = 12; CompartmentId = 4; RouteMetric = 500; State = 'Alive' }
                )
                $interfaces = @(
                    [PSCustomObject]@{ InterfaceIndex = 10; CompartmentId = 4; AddressFamily = 'IPv4'; InterfaceMetric = 1; ConnectionState = 'Connected' }
                    [PSCustomObject]@{ InterfaceIndex = 11; CompartmentId = 4; AddressFamily = 'IPv4'; InterfaceMetric = 10; ConnectionState = 'Connected' }
                    [PSCustomObject]@{ InterfaceIndex = 12; CompartmentId = 4; AddressFamily = 'IPv4'; InterfaceMetric = 100; ConnectionState = 'Connected' }
                )

                $result = Select-SdnGatewayIPv4Route -PeerIPAddress '10.20.30.44' -CompartmentId 4 -Routes $routes -IPInterfaces $interfaces
                $result.Status | Should -Be 'Selected'
                $result.SelectedRoute.DestinationPrefix | Should -Be '10.20.30.44/32'
                $result.SelectedRoute.NextHop | Should -Be '192.0.2.3'
            }
        }

        It "Distinguishes an empty route inventory from an unavailable route-interface association" {
            InModuleScope SdnDiag.Health {
                $emptyResult = Select-SdnGatewayIPv4Route -PeerIPAddress '10.20.30.44' -CompartmentId 4 `
                    -Routes @() -IPInterfaces @()
                $emptyResult.Status | Should -Be 'RouteMissing'

                $route = [PSCustomObject]@{
                    DestinationPrefix = '10.20.30.0/24'
                    NextHop = '192.0.2.1'
                    InterfaceIndex = 10
                    CompartmentId = 4
                    RouteMetric = 5
                    State = 'Alive'
                }
                $unassociatedResult = Select-SdnGatewayIPv4Route -PeerIPAddress '10.20.30.44' -CompartmentId 4 `
                    -Routes @($route) -IPInterfaces @()
                $unassociatedResult.Status | Should -Be 'Unknown'
                $unassociatedResult.ReasonCode | Should -Be 'RouteInterfaceAssociationUnavailable'
            }
        }

        It "Reports equally preferred route paths as ambiguous" {
            InModuleScope SdnDiag.Health {
                $routes = @(
                    [PSCustomObject]@{ DestinationPrefix = '10.20.30.0/24'; NextHop = '192.0.2.1'; InterfaceIndex = 10; CompartmentId = 4; RouteMetric = 5; State = 'Alive' }
                    [PSCustomObject]@{ DestinationPrefix = '10.20.30.0/24'; NextHop = '192.0.2.2'; InterfaceIndex = 11; CompartmentId = 4; RouteMetric = 5; State = 'Alive' }
                )
                $interfaces = @(
                    [PSCustomObject]@{ InterfaceIndex = 10; CompartmentId = 4; AddressFamily = 'IPv4'; InterfaceMetric = 10; ConnectionState = 'Connected' }
                    [PSCustomObject]@{ InterfaceIndex = 11; CompartmentId = 4; AddressFamily = 'IPv4'; InterfaceMetric = 10; ConnectionState = 'Connected' }
                )

                $result = Select-SdnGatewayIPv4Route -PeerIPAddress '10.20.30.44' -CompartmentId 4 -Routes $routes -IPInterfaces $interfaces
                $result.Status | Should -Be 'Ambiguous'
                $result.CandidatePaths.Count | Should -Be 2
            }
        }

        It "Fails only after repeated unresolved observations for the selected off-link next hop" {
            InModuleScope SdnDiag.Health {
                function Get-RemoteAccessRoutingDomain { [CmdletBinding()] param() }
                function Get-NetCompartment { [CmdletBinding()] param() }
                function Get-BgpPeer { [CmdletBinding()] param([switch]$AllRoutingDomains, [string]$RoutingDomain) }
                function Get-NetIPAddress {
                    [CmdletBinding()]
                    param([string]$IPAddress, [object]$AssociatedIPInterface, [string]$AddressFamily, [switch]$IncludeAllCompartments)
                }
                function Get-NetIPInterface {
                    [CmdletBinding()]
                    param([object]$AssociatedIPAddress, [object]$AssociatedRoute, [string]$AddressFamily, [int]$CompartmentId, [switch]$IncludeAllCompartments)
                }
                function Get-NetRoute {
                    [CmdletBinding()]
                    param([string]$AddressFamily, [int]$CompartmentId, [string]$PolicyStore)
                }
                function Get-NetNeighbor {
                    [CmdletBinding()]
                    param([object]$AssociatedIPInterface, [switch]$IncludeAllCompartments, [string]$AddressFamily)
                }

                $Global:PesterGatewayNeighborState = 'Unreachable'
                $Global:PesterGatewayNextHop = '192.0.2.1'
                $Global:PesterGatewayProtocolIFType = 6
                $Global:PesterGatewayNeighborDiscoverySupported = $true
                $Global:PesterGatewayDomainStatus = 'Enabled'
                $Global:PesterGatewayPeerCount = 1
                $Global:PesterGatewayNeighborReadCount = 0
                Mock Get-Command {
                    if ($Name -eq 'Get-BgpPeer') {
                        return [PSCustomObject]@{ Parameters = @{ AllRoutingDomains = $true } }
                    }
                    return $null
                }
                Mock Get-RemoteAccessRoutingDomain {
                    [PSCustomObject]@{ RoutingDomain = 'tenant-a'; RoutingDomainID = '11111111-1111-1111-1111-111111111111'; RoutingStatus = $Global:PesterGatewayDomainStatus }
                }
                Mock Get-NetCompartment {
                    [PSCustomObject]@{ CompartmentId = 4; CompartmentGuid = '{11111111-1111-1111-1111-111111111111}'; CompartmentDescription = 'tenant-a' }
                }
                Mock Get-BgpPeer {
                    1..$Global:PesterGatewayPeerCount | ForEach-Object {
                        [PSCustomObject]@{
                            RoutingDomain = 'tenant-a'
                            PeerName = "peer-$_"
                            PeerIPAddress = "10.20.30.$(43 + $_)"
                            LocalIPAddress = '10.20.30.1'
                            ConnectivityStatus = 'Disconnected'
                            OperationMode = 'Active'
                        }
                    }
                }
                Mock Get-NetIPAddress {
                    if ($PesterBoundParameters.ContainsKey('IPAddress')) {
                        return [PSCustomObject]@{ IPAddress = '10.20.30.1'; InterfaceIndex = 5 }
                    }
                    return [PSCustomObject]@{ IPAddress = '192.0.2.10'; InterfaceIndex = 10 }
                }
                Mock Get-NetIPInterface {
                    if ($PesterBoundParameters.ContainsKey('AssociatedIPAddress')) {
                        return [PSCustomObject]@{ CompartmentId = 4; InterfaceIndex = 5; InterfaceAlias = 'BGP-Source'; AddressFamily = 'IPv4'; InterfaceMetric = 10; ConnectionState = 'Connected'; ProtocolIFType = 6; NeighborDiscoverySupported = $true }
                    }
                    if ($PesterBoundParameters.ContainsKey('AssociatedRoute')) {
                        return [PSCustomObject]@{ CompartmentId = 4; InterfaceIndex = 10; InterfaceAlias = 'DVLAB-GW-Uplink'; AddressFamily = 'IPv4'; InterfaceMetric = 10; ConnectionState = 'Connected'; ProtocolIFType = $Global:PesterGatewayProtocolIFType; NeighborDiscoverySupported = $Global:PesterGatewayNeighborDiscoverySupported }
                    }
                    return [PSCustomObject]@{ CompartmentId = 4; InterfaceIndex = 10; AddressFamily = 'IPv4'; InterfaceMetric = 10; ConnectionState = 'Connected'; ProtocolIFType = 6; NeighborDiscoverySupported = $true }
                }
                Mock Get-NetRoute {
                    [PSCustomObject]@{ DestinationPrefix = '10.20.30.0/24'; NextHop = $Global:PesterGatewayNextHop; InterfaceIndex = 10; CompartmentId = 4; RouteMetric = 5; State = 'Alive' }
                }
                Mock Get-NetNeighbor {
                    if ($Global:PesterGatewayNeighborState) {
                        $Global:PesterGatewayNeighborReadCount++
                        $neighborAddress = if ($Global:PesterGatewayNextHop -eq '0.0.0.0') { '10.20.30.44' } else { $Global:PesterGatewayNextHop }
                        $state = if ($Global:PesterGatewayPeerCount -gt 1 -and $Global:PesterGatewayNeighborReadCount -gt 3) { 'Reachable' } else { $Global:PesterGatewayNeighborState }
                        [PSCustomObject]@{ IPAddress = $neighborAddress; State = $state; LinkLayerAddress = '00:11:22:33:44:55' }
                    }
                }

                $result = Test-SdnGatewayPeerNextHopArp -SampleCount 3 -SampleIntervalSeconds 0 -SettlingPeriodSeconds 0
                $result.Result | Should -Be 'FAIL'
                $result.Properties[0].NeighborTargetIPAddress | Should -Be '192.0.2.1'
                $result.Properties[0].NeighborTargetKind | Should -Be 'L3NextHop'
                $result.Properties[0].SampleHistoryUtc.Count | Should -Be 3
                $result.Properties[0].ReasonCode | Should -Be 'PersistentUnresolvedNextHop'
                $result.Properties[0].EgressSourceAddresses | Should -Contain '192.0.2.10'
                $result.Properties[0].BgpLocalInterfaceIndex | Should -Be 5

                $Global:PesterGatewayPeerCount = 2
                $Global:PesterGatewayNeighborReadCount = 0
                $recoveryResult = Test-SdnGatewayPeerNextHopArp -SampleCount 3 -SampleIntervalSeconds 0 -SettlingPeriodSeconds 0
                $recoveryResult.Properties[0].Result | Should -Be 'FAIL'
                $recoveryResult.Properties[1].Result | Should -Be 'PASS'
                $Global:PesterGatewayNeighborReadCount | Should -Be 6

                $Global:PesterGatewayPeerCount = 1
                $Global:PesterGatewayNeighborReadCount = 0
                $Global:PesterGatewayProtocolIFType = 24
                $Global:PesterGatewayNeighborDiscoverySupported = $false
                $nonArpResult = Test-SdnGatewayPeerNextHopArp -SampleCount 2 -SampleIntervalSeconds 0 -SettlingPeriodSeconds 0
                $nonArpResult.Properties[0].Result | Should -Be 'NotApplicable'
                $nonArpResult.Properties[0].ReasonCode | Should -Be 'PathDoesNotUseEthernetArp'
                $Global:PesterGatewayProtocolIFType = 6
                $Global:PesterGatewayNeighborDiscoverySupported = $true

                $Global:PesterGatewayDomainStatus = 'Disabled'
                $inactiveDomainResult = Test-SdnGatewayPeerNextHopArp -SampleCount 2 -SampleIntervalSeconds 0 -SettlingPeriodSeconds 0
                $inactiveDomainResult.Properties[0].Result | Should -Be 'NotApplicable'
                $inactiveDomainResult.Properties[0].ReasonCode | Should -Be 'PeerOrDomainNotExpectedToConnect'
                $Global:PesterGatewayDomainStatus = 'Enabled'

                $Global:PesterGatewayNeighborState = 'Reachable'
                $Global:PesterGatewayNextHop = '0.0.0.0'
                $onLinkResult = Test-SdnGatewayPeerNextHopArp -SampleCount 2 -SampleIntervalSeconds 0 -SettlingPeriodSeconds 0
                $onLinkResult.Result | Should -Be 'PASS'
                $onLinkResult.Properties[0].NeighborTargetIPAddress | Should -Be '10.20.30.44'
                $onLinkResult.Properties[0].NeighborTargetKind | Should -Be 'OnLinkPeer'

                $Global:PesterGatewayNextHop = '192.0.2.1'
                $Global:PesterGatewayNeighborState = 'Stale'
                $staleResult = Test-SdnGatewayPeerNextHopArp -SampleCount 2 -SampleIntervalSeconds 0 -SettlingPeriodSeconds 0
                $staleResult.Result | Should -Be 'PASS'
                $staleResult.Properties[0].ReasonCode | Should -Be 'NeighborHasValidMac'

                $Global:PesterGatewayNeighborState = $null
                $missingResult = Test-SdnGatewayPeerNextHopArp -SampleCount 2 -SampleIntervalSeconds 0 -SettlingPeriodSeconds 0
                $missingResult.Result | Should -Be 'UNKNOWN'
                $missingResult.Properties[0].ReasonCode | Should -Be 'NeighborNotObserved'
                Remove-Variable -Name PesterGatewayNeighborState -Scope Global
                Remove-Variable -Name PesterGatewayNextHop -Scope Global
                Remove-Variable -Name PesterGatewayProtocolIFType -Scope Global
                Remove-Variable -Name PesterGatewayNeighborDiscoverySupported -Scope Global
                Remove-Variable -Name PesterGatewayDomainStatus -Scope Global
                Remove-Variable -Name PesterGatewayPeerCount -Scope Global
                Remove-Variable -Name PesterGatewayNeighborReadCount -Scope Global
            }
        }
    }

Describe 'Health - Test-VMNetAdapterDuplicateMacAddress unique addresses' {
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
