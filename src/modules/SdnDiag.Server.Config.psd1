# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

@{
    Name = "Server"
    WindowsFeature = @(
        "Hyper-V"
    )
    RequiredModules = @(
        "Hyper-V",
        "HnvDiagnostics"
    )
    Properties = @{
        CommonPaths = @{}
        EventLogProviders = @(
            "Microsoft-Windows-Hyper-V*"
            "Microsoft-Windows-NetworkController-NcHostAgent-Admin"
            "Microsoft-Windows-Networking-NetworkAtc*"
        )
        RegKeyPaths = @(
            "HKLM:\Software\Microsoft\NetworkController"
            "HKLM:\SYSTEM\CurrentControlSet\Services\DnsProxy"
            "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent"
            "HKLM:\SYSTEM\CurrentControlSet\Services\SlbHostAgent"
        )
        Services = @{
            NcHostAgent = @{
                Properties = @{
                    DisplayName = "NC Host Agent"
                }
            }
            SlbHostAgent = @{
                Properties = @{
                    DisplayName = "Software Load Balancer Host Agent"
                }
            }
        }
        EtwTraceProviders = @{
            nchostagent = @{
                isOptional = $false
                Providers = @(
                    "{28F7FB0F-EAB3-4960-9693-9289CA768DEA}" # Microsoft.Windows.NetworkController.HostAgent.Service
                    "{A6527853-5B2B-46E5-9D77-A4486E012E73}" # Microsoft.Windows.NetworkController.HostAgent.VNetPlugin
                    "{dbc217a8-018f-4d8e-a849-acea31bc93f9}" # Microsoft.Windows.NetworkController.HostAgent.VSwitchPlugin
                    "{41DC7652-AAF6-4428-BBBB-CFBDA322F9F3}" # Microsoft.Windows.NetworkController.HostAgent.FirewallPlugin
                    "{F2605199-8A9B-4EBD-B593-72F32DEEC058}" # Microsoft.Windows.NetworkController.HostAgent.ServiceInsertionPlugin
                    "{f6be3d13-c3d4-44bb-ad4d-3498b51f981e}" # Microsoft.Windows.NetworkController.HostAgent.GatewayPlugin
                )
                Level = 4
                Keywords = "0xFFFFFFFFFFFFFFFF"
            }
            nvsp = @{
                isOptional = $false
                Providers = @(
                    "{1F387CBC-6818-4530-9DB6-5F1058CD7E86}" # Microsoft.Windows.Hyper-V.VmSwitchWpp
                    "{6C28C7E5-331B-4437-9C69-5352A2F7F296}" # Microsoft-Windows-Hyper-V-VmsIf
                )
                Level = 4
                Keywords = "0xFFFFFFFFFFFFFFFF"
            }
            slbhostagent = @{
                isOptional = $false
                Providers = @(
                    "{2380c5ee-ab89-4d14-b2e6-142200cb703c}" # Microsoft-Windows-SoftwareLoadBalancer-HostPlugin
                )
                Level = 4
                Keywords = "0xFFFFFFFFFFFFFFFF"
            }
            vfpext = @{
                isOptional = $false
                Providers = @(
                    "{9F2660EA-CFE7-428F-9850-AECA612619B0}" # Microsoft-Windows-Hyper-V-VfpExt
                    "{67DC0D66-3695-47C0-9642-33F76F7BD7AD}" # MicrosoftWindowsHyperVVmSwitch
                )
                Level = 4
                Keywords = "0xFFFFFFFFFFFFFFFF"
            }
        }
    }
    ResourceName = "Servers"
}
