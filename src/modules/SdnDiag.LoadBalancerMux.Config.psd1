# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

@{
    Name = "LoadBalancerMux"
    WindowsFeature = @(
        "SoftwareLoadBalancer"
    )
    RequiredModules = @()
    Properties = @{
        CommonPaths = @{}
        EventLogProviders = @(
            "Microsoft-Windows-SlbMux*"
        )
        RegKeyPaths = @(
            "HKLM:\Software\Microsoft\NetworkController"
            "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent"
            "HKLM:\SYSTEM\CurrentControlSet\Services\SlbMux"
            "HKLM:\SYSTEM\CurrentControlSet\Services\SlbMuxDriver"
        )
        Services = @{
            SlbMux = @{
                DisplayName = "Software Load Balancer Host Agent"
            }
        }
        EtwTraceProviders = @{
            SlbMux = @{
                isOptional = $false
                Providers = @(
                    "{645b8679-5451-4c36-9857-a90e7dbf97bc}" # Microsoft-Windows-SlbMuxDriver
                    "{6C2350F8-F827-4B74-AD0C-714A92E22576}" # Microsoft-Windows-SlbMux
                    "{2E67FCF3-C48E-4B2D-A689-A91D07EDB910}" # Microsoft-Windows-RasRoutingProtocols-BGP
                    "{9FD2B528-8D3D-42D0-8FDF-5B1998004278}" # Microsoft.Windows.Networking.RAS.Routing.BGP
                )
                Level = $null
                Keywords = $null
            }
        }
    }
    ResourceName = "LoadBalancerMuxes"
}
