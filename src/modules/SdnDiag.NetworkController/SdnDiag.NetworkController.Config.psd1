# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

@{
    Name = "NetworkController"
    WindowsFeature = @(
        "NetworkController"
    )
    RequiredModules = @(
        "NetworkController"
    )
    Properties = @{
        apiResources = @{
            AccessControlLists = @{
                uri = "accessControlLists"
                minVersion = "v1"
                operationId = $false
                includeInResourceDump = $true
            }
            AuditingSettingsConfig = @{
                uri = "auditingSettings/configuration"
                minVersion = "v3"
                operationId = $false
                includeInResourceDump = $true
            }
            Credentials = @{
                uri = "credentials"
                minVersion = "v1"
                operationId = $false
                includeInResourceDump = $true
            }
            Discovery = @{
                uri = "discovery"
                minVersion = ""
                operationId = $false
                includeInResourceDump = $true
            }
            GatewayPools = @{
                uri = "gatewayPools"
                minVersion = "v1"
                operationId = $false
                includeInResourceDump = $true
            }
            Gateways = @{
                uri = "gateways"
                minVersion = "v1"
                operationId = $false
                includeInResourceDump = $true
            }
            IDNSServerConfig = @{
                uri = "iDNSServer/configuration"
                minVersion = "v1"
                operationId = $false
                includeInResourceDump = $true
            }
            internalResourceInstances = @{
                uri = "internalResourceInstances"
                minVersion = "v1"
                operationId = $false
                includeInResourceDump = $true
            }
            LearnedIPAddresses = @{
                uri = "learnedIPAddresses"
                minVersion = "v5"
                operationId = $false
                includeInResourceDump = $true
            }
            LoadBalancerManagerConfig = @{
                uri = "loadBalancerManager/config"
                minVersion = "v1"
                operationId = $false
                includeInResourceDump = $true
            }
            LoadBalancerMuxes = @{
                uri = "loadBalancerMuxes"
                minVersion = "v1"
                operationId = $false
                includeInResourceDump = $true
            }
            LoadBalancers = @{
                uri = "loadBalancers"
                minVersion = "v1"
                operationId = $false
                includeInResourceDump = $true
            }
            LogicalNetworks = @{
                uri = "logicalNetworks"
                minVersion = "v1"
                operationId = $false
                includeInResourceDump = $true
            }
            MacPools = @{
                uri = "macPools"
                minVersion = "v1"
                operationId = $false
                includeInResourceDump = $true
            }
            NetworkControllerBackup = @{
                uri = "networkControllerBackup"
                minVersion = "v1"
                operationId = $false
                includeInResourceDump = $true
            }
            NetworkControllerRestore = @{
                uri = "networkControllerRestore"
                minVersion = "v1"
                operationId = $false
                includeInResourceDump = $true
            }
            NetworkControllerStatistics = @{
                uri = "monitoring/networkControllerStatistics"
                minVersion = "v1"
                operationId = $false
                includeInResourceDump = $true
            }
            NetworkInterfaces = @{
                uri = "networkInterfaces"
                minVersion = "v1"
                operationId = $false
                includeInResourceDump = $true
            }
            Operations = @{
                uri = "operations"
                minVersion = "v1"
                operationId = $false
                includeInResourceDump = $false
            }
            OperationResults = @{
                uri = "operationResults"
                minVersion = "v1"
                operationId = $true
                includeInResourceDump = $false
            }
            PublicIPAddresses = @{
                uri = "publicIPAddresses"
                minVersion = "v1"
                operationId = $false
                includeInResourceDump = $true
            }
            SecurityTags = @{
                uri = "securityTags"
                minVersion = "v5"
                operationId = $false
                includeInResourceDump = $true
            }
            Servers = @{
                uri = "Servers"
                minVersion = "v1"
                operationId = $false
                includeInResourceDump = $true
            }
            ServiceInsertions = @{
                uri = "serviceInsertions"
                minVersion = "v1"
                operationId = $false
                includeInResourceDump = $true
            }
            SlbState = @{
                uri = "diagnostics/slbState"
                minVersion = "v1"
                operationId = $false
                includeInResourceDump = $false
            }
            SlbStateResults = @{
                uri = "diagnostics/slbStateResults"
                minVersion = "v1"
                operationId = $true
                includeInResourceDump = $false
            }
            RouteTables = @{
                uri = "routeTables"
                minVersion = "v1"
                operationId = $false
                includeInResourceDump = $true
            }
            VirtualGateways = @{
                uri = "virtualGateways"
                minVersion = "v1"
                operationId = $false
                includeInResourceDump = $true
            }
            VirtualNetworkManagerConfig = @{
                uri = "virtualNetworkManager/configuration"
                minVersion = "v1"
                operationId = $false
                includeInResourceDump = $true
            }
            VirtualNetworks = @{
                uri = "virtualNetworks"
                minVersion = "v1"
                operationId = $false
                includeInResourceDump = $true
            }
            VirtualServers = @{
                uri = "virtualServers"
                minVersion = "v1"
                operationId = $false
                includeInResourceDump = $true
            }
            VirtualSwitchManagerConfig = @{
                uri = "virtualSwitchManager/configuration"
                minVersion = "v1"
                operationId = $false
                includeInResourceDump = $true
            }
        }
        CommonPaths = @{
            serviceFabricLogDirectory = "C:\ProgramData\Microsoft\Service Fabric\log\Traces"
        }
        EventLogProviders = @(
            "Microsoft-Windows-NetworkController*"
            "Microsoft-ServiceFabric*"
        )
        NetControllerStatePath = "C:\Windows\Tracing\SDNDiagnostics\NetworkControllerState"
        RegKeyPaths = @(
            "HKLM:\Software\Microsoft\NetworkController"
            "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent"
            "HKLM:\SYSTEM\CurrentControlSet\Services\Network Controller"
        )
        Services = @{
            FabricHostSvc = @{
                Properties = @{
                    DisplayName = "Service Fabric Host Service"
                }
            }
        }
    }
}
