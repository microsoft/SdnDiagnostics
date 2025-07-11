# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

@{
    Name = "Gateway"
    WindowsFeature = @(
        "RemoteAccess"
    )
    RequiredModules = @()
    Properties = @{
        CommonPaths = @{
            RasGatewayTraces = "C:\Windows\Tracing"
        }
        EventLogProviders = @(
            "Microsoft-Windows-RasAgileVpn*"
            "Microsoft-Windows-RemoteAccess*"
            "Microsoft-Windows-VPN*"
        )
        RegKeyPaths = @(
            "HKLM:\Software\Microsoft\NetworkController"
            "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent"
        )
        Services = @{
            RemoteAccess = @{
                Properties = @{
                    DisplayName = "Routing and Remote Access"
                }
            }
        }
        EtwTraceProviders = @{
            IKE = @{
                isOptional = $false
                Providers = @(
                    "{106b464d-8043-46b1-8cb8-e92a0cd7a560}" # IKEEXT WPP / BFE
                )
                Level = 255
                Keywords = "0xFFFFFFFFFFFFFFFF"
            }
            Rasgateway = @{
                isOptional = $false
                Providers = @(
                    "{EB171376-3B90-4169-BD76-2FB821C4F6FB}" # BGP
                    "{24989972-0967-4E21-A926-93854033638E}" # Microsoft-Windows-RRAS
                    "{F3F35A3B-6D33-4C32-BC81-21513D8BD708}" # Microsoft-Windows-GatewayHealthMonitor
                    "{58ac8283-c536-5244-63c2-eb41247e4a10}" # Microsoft-Windows-GatewayService
                    "{2E67FCF3-C48E-4B2D-A689-A91D07EDB910}" # Microsoft-Windows-RasRoutingProtocols-BGP
                    "{9FD2B528-8D3D-42D0-8FDF-5B1998004278}" # Microsoft.Windows.Networking.RAS.Routing.BGP
                    "{B5325CD6-438E-4EC1-AA46-14F46F2570E4}" # Microsoft.Windows.Networking.RAS.RASServer.AgileVPN
                )
                Level = 255
                Keywords = "0xFFFFFFFFFFFFFFFF"
            }
        }
    }
    ResourceName = "Gateways"
}
