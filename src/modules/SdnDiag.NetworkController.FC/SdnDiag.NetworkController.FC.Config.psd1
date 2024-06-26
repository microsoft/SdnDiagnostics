# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

@{
    Name = "NetworkControllerFC"
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
                }
            }
            SDNControllerService = @{
                Properties = @{
                    DisplayName = "SDNControllerService"
                }
            }
            SDNFirewallService = @{
                Properties = @{
                    DisplayName = "SDNFirewallService"
                }
            }
            SDNFnmService = @{
                Properties = @{
                    DisplayName = "SDNFnmService"
                }
            }
            SDNGatewayManager = @{
                Properties = @{
                    DisplayName = "SDNGatewayManager"
                }
            }
            SDNHelperService = @{
                Properties = @{
                    DisplayName = "SDNHelperService"
                }
            }
            SDNServiceInsertion = @{
                Properties = @{
                    DisplayName = "SDNServiceInsertion"
                }
            }
            SDNSlbManagerService = @{
                Properties = @{
                    DisplayName = "SDNSlbManagerService"
                }
            }
            SDNVSwitchService = @{
                Properties = @{
                    DisplayName = "SDNVSwitchService"
                }
            }
        }
    }
}
