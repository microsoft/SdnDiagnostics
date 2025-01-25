# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

@{
    Name = "NetworkController_FC"
    WindowsFeature = @(
        "NetworkController"
    )
    RequiredModules = @(
        "NetworkController"
    )
    Properties = @{
        CommonPaths = @{}
        EventLogProviders = @(
            'Microsoft-Windows-FailoverClustering*',
            'Microsoft-Windows-FailoverClustering-Manager*',
            'NetworkControllerFc'
        )
        RegKeyPaths = @(
            'HKLM:\Cluster\NetworkController'
        )
        Services = @{
            SDNApiService = @{
                Properties = @{
                    DisplayName = "SDNApiService"
                    OwnerGroupName = "ApiService"
                }
            }
            SDNControllerService = @{
                Properties = @{
                    DisplayName = "SDNControllerService"
                    OwnerGroupName = "ControllerService"
                }
            }
            SDNFirewallService = @{
                Properties = @{
                    DisplayName = "SDNFirewallService"
                    OwnerGroupName = "FirewallService"
                }
            }
            SDNFnmService = @{
                Properties = @{
                    DisplayName = "SDNFnmService"
                    OwnerGroupName = "FnmService"
                }
            }
            SDNGatewayManager = @{
                Properties = @{
                    DisplayName = "SDNGatewayManager"
                    OwnerGroupName = "GatewayManager"
                }
            }
            SDNHelperService = @{
                Properties = @{
                    DisplayName = "SDNHelperService"
                    OwnerGroupName = ""
                }
            }
            SDNServiceInsertion = @{
                Properties = @{
                    DisplayName = "SDNServiceInsertion"
                    OwnerGroupName = "ServiceInsertion"
                }
            }
            SDNSlbManagerService = @{
                Properties = @{
                    DisplayName = "SDNSlbManagerService"
                    OwnerGroupName = "SlbManagerService"
                }
            }
            SDNVSwitchService = @{
                Properties = @{
                    DisplayName = "SDNVSwitchService"
                    OwnerGroupName = "VSwitchService"
                }
            }
        }
    }
}
