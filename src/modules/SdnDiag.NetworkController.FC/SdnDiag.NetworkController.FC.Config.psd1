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
            'Microsoft-Windows-FailoverClustering/Diagnostic',
            'Microsoft-Windows-FailoverClustering/Operational',
            'Microsoft-Windows-FailoverClustering-Manager/Admin',
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
