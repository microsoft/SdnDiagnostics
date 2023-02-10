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
            "Application"
            "Microsoft-Windows-Hyper-V*"
            "System"
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
            DnsProxy = @{
                Properties = @{
                    DisplayName = "Dns Proxy"
                }
            }
        }
        EtwTraceProviders =@{
            nchostagent = @{
                isOptional = $false
                Providers = @(
                    "{28F7FB0F-EAB3-4960-9693-9289CA768DEA}"
                    "{A6527853-5B2B-46E5-9D77-A4486E012E73}"
                    "{dbc217a8-018f-4d8e-a849-acea31bc93f9}"
                    "{41DC7652-AAF6-4428-BBBB-CFBDA322F9F3}"
                    "{F2605199-8A9B-4EBD-B593-72F32DEEC058}"
                )
                Level = 4
                Keywords = "0xFFFFFFFFFFFFFFFF"
            }
            nvsp = @{
                isOptional = $false
                Providers = @(
                    "{1F387CBC-6818-4530-9DB6-5F1058CD7E86}"
                    "{6C28C7E5-331B-4437-9C69-5352A2F7F296}"
                )
                Level = 4
                Keywords = "0xFFFFFFFFFFFFFFFF"
            }
            slbhostagent = @{
                isOptional = $false
                Providers = @(
                    "{2380c5ee-ab89-4d14-b2e6-142200cb703c}"
                )
                Level = 4
                Keywords = "0xFFFFFFFFFFFFFFFF"
            }
            vfpext = @{
                isOptional = $false
                Providers = @(
                    "{9F2660EA-CFE7-428F-9850-AECA612619B0}"
                    "{67DC0D66-3695-47C0-9642-33F76F7BD7AD}"
                )
                Level = 4
                Keywords = "0xFFFFFFFFFFFFFFFF"
            }
        }
    }
}
