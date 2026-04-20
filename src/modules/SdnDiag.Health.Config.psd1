# Copyright='© Microsoft Corporation. All rights reserved.'
# Licensed under the MIT License.

@{
    HealthValidations = @{

        # COMMON TESTS

        'Test-SdnDiagnosticsCleanupTaskEnabled' = @{
            Description = "Ensure that scheduled task is enabled to automatically clean up and prune diagnostic log files."
            Impact = "Unconstrained log files may grow and consume disk space."
            PublicDocUrl = ""
        }
        'Test-SdnNetworkControllerApiNameResolution' = @{
            Description = "Ensure that the Network Controller URL is resolvable."
            Impact = "Calls to Network Controller API will fail resulting in policy configuration failures and unable to manage SDN resources."
            PublicDocUrl = ""
        }
        'Test-SdnNonSelfSignedCertificateInTrustedRootStore' = @{
            Description = "Ensure that only trusted root certificates exist in the host Trusted Root CA store."
            Impact = "Network Controller will have issues communicating to hosts resulting in policy configuration failures."
            PublicDocUrl = "https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/iis/site-behavior-performance/http-403-forbidden-access-website#cause-2-non-self-signed-certificates-are-in-trusted-root-certification-authorities-certificate-store"
        }
        'Test-SdnServiceState' = @{
            Description = "Ensure that required services are running on the SDN infrastructure node(s)."
            Impact = "SDN services and functionality will be impacted without the service running."
            PublicDocUrl = ""
        }
        'Test-SdnCertificateExpired' = @{
            Description = "Ensure that SDN infrastructure node certificates are valid and not expired."
            Impact = "Network Controller may have issues communicating and programming policies to SDN infrastructure nodes resulting in impact to workloads and services."
            PublicDocUrl = "https://learn.microsoft.com/en-us/azure/azure-local/manage/update-sdn-infrastructure-certificates"
        }
        'Test-SdnCertificateMultiple' = @{
            Description = "Ensure that only one certificate with the same subject name and NetworkController OID exists in the SDN infrastructure node certificate store."
            Impact = "Network Controller may have issues communicating and programming policies to SDN infrastructure nodes resulting in impact to workloads and services."
            PublicDocUrl = "https://learn.microsoft.com/en-us/azure/azure-local/manage/update-sdn-infrastructure-certificates"
        }

        # GATEWAY TESTS

        'Test-SdnAdapterPerformanceSetting' = @{
            Description = "Ensure that network adapter performance settings are configured as recommended on the SDN node(s)."
            Impact = "You may not achieve optimal performance for network traffic flowing through the SDN Node(s)."
            PublicDocUrl = ""
        }

        # LOAD BALANCER MUX TESTS

        'Test-SdnMuxConnectionStateToRouter' = @{
            Description = "Ensure that each Load Balancer Mux has an active BGP connection to the switch over TCP port 179."
            Impact = "Public IP addresses may not be routable as Load Balancer Muxes are not advertising the public IP addresses to the switch."
            PublicDocUrl = "https://learn.microsoft.com/en-us/azure-stack/hci/manage/troubleshoot-software-load-balancer"
        }
        'Test-SdnMuxConnectionStateToSlbManager' = @{
            Description = "Ensure that SLB Manager connectivity to Mux(es) over TCP port 8560 is established."
            Impact = "SLB Manager will not be able to program VIP:DIP mappings to the Load Balancer Mux(es) which will impact routing of Virtual IPs."
            PublicDocUrl = "https://learn.microsoft.com/en-us/azure-stack/hci/manage/troubleshoot-software-load-balancer"
        }

        # NETWORK CONTROLLER TESTS

        'Test-SdnNetworkControllerNodeRestInterface' = @{
            Description = "Ensure that Network Controller node(s) have the required network adapter for the REST interface."
            Impact = "Failover of the NB API will not occur if the Network Controller node(s) are missing the Network Adapter that is required for the REST interface."
            PublicDocUrl = "https://learn.microsoft.com/en-us/powershell/module/networkcontroller/set-networkcontrollernode"
        }
        'Test-SdnServiceFabricApplicationHealth' = @{
            Description = "Ensure that the Network Controller Service Fabric application is healthy."
            Impact = "Network Controller services and functionality may be impacted."
            PublicDocUrl = ""
        }
        'Test-SdnServiceFabricClusterHealth' = @{
            Description = "Ensure that the Service Fabric cluster for Network Controller is healthy."
            Impact = "Network Controller services and functionality may be impacted."
            PublicDocUrl = ""
        }
        'Test-SdnServiceFabricNodeStatus' = @{
            Description = "Ensure that Service Fabric node(s) are online and participating in the cluster."
            Impact = "Minimum amount of nodes are required to maintain quorum and cluster availability. Services will be in read-only state if quorum is lost and may result in data loss."
            PublicDocUrl = "https://learn.microsoft.com/en-us/azure/service-fabric/service-fabric-disaster-recovery"
        }
        'Test-SdnResourceConfigurationState' = @{
            Description = "Ensure that infrastructure resources report configuration state as Success."
            Impact = "SDN services and functionality may be impacted."
            PublicDocUrl = "https://learn.microsoft.com/en-us/windows-server/networking/sdn/troubleshoot/troubleshoot-windows-server-software-defined-networking-stack#hoster-validate-system-health"
        }
        'Test-SdnResourceProvisioningState' = @{
            Description = "Ensure that infrastructure resources report provisioning state as Succeeded."
            Impact = "SDN services and functionality may be impacted."
            PublicDocUrl = "https://learn.microsoft.com/en-us/windows-server/networking/sdn/troubleshoot/troubleshoot-windows-server-software-defined-networking-stack#hoster-validate-system-health"
        }
        'Test-NetworkInterfaceAPIDuplicateMacAddress' = @{
            Description = "Ensure that MAC addresses are unique for network interfaces in the API."
            Impact = "Policy configuration failures may be reported by Network Controller when applying policies to the Hyper-v host. Network Interfaces reporting configurationState failure will not be routable."
            PublicDocUrl = ""
        }

        # SERVER TESTS

        'Test-SdnEncapOverhead' = @{
            Description = "Ensure that EncapOverhead and JumboPacket values are configured correctly on Hyper-V hosts."
            Impact = "Intermittent packet loss may occur under certain conditions when routing traffic within the logical network."
            PublicDocUrl = "https://learn.microsoft.com/en-us/windows-server/networking/sdn/troubleshoot/troubleshoot-windows-server-software-defined-networking-stack#check-mtu-and-jumbo-frame-support-on-hnv-provider-logical-network"
        }
        'Test-SdnHostAgentConnectionStateToApiService' = @{
            Description = "Ensure that the Network Controller Host Agent is connected to the Network Controller API service."
            Impact = "Policy configuration may not be pushed to the Hyper-V host(s) if no southbound connectivity is available."
            PublicDocUrl = ""
        }
        'Test-SdnProviderNetwork' = @{
            Description = "Ensure that the logical network supports VXLAN or NVGRE encapsulated traffic."
            Impact = "Intermittent packet loss may occur under certain conditions when routing traffic within the logical network."
            PublicDocUrl = "https://learn.microsoft.com/en-us/windows-server/networking/sdn/troubleshoot/troubleshoot-windows-server-software-defined-networking-stack#check-mtu-and-jumbo-frame-support-on-hnv-provider-logical-network"
        }
        'Test-VfpDuplicateMacAddress' = @{
            Description = "Ensure that MAC addresses are unique within Virtual Filtering Platform (VFP)."
            Impact = "Policy configuration failures may be reported by Network Controller when applying policies to the Hyper-v host. In addition, network traffic may be impacted."
            PublicDocUrl = ""
        }
        'Test-SdnVfpEnabledVMSwitch' = @{
            Description = "Ensure that at least one VMSwitch with VFP enabled is present on Hyper-V host(s)."
            Impact = "Policy configuration failures may be reported by Network Controller when applying policies to the Hyper-v host."
            PublicDocUrl = ""
        }
        'Test-SdnVfpEnabledVMSwitchMultiple' = @{
            Description = "Ensure that only one VFP-enabled virtual switch is present on Hyper-V host(s)."
            Impact = "Policy configuration failures may be reported by Network Controller when applying policies to the Hyper-v host."
            PublicDocUrl = ""
        }
        'Test-VMNetAdapterDuplicateMacAddress' = @{
            Description = "Ensure that data-plane VM network adapter MAC addresses are unique on Hyper-V host(s)."
            Impact = "Policy configuration failures may be reported by Network Controller when applying policies to the Hyper-v host. In addition, network traffic may be impacted for the interfaces that are duplicated."
            PublicDocUrl = ""
        }
        'Test-ServerHostId' = @{
            Description = "Ensure that HostID is configured correctly on Hyper-V hosts."
            Impact = "Mismatch of HostId between Hyper-V host(s) and Network Controller will result in policy configuration failures."
            PublicDocUrl = "https://learn.microsoft.com/en-us/windows-server/networking/sdn/troubleshoot/troubleshoot-windows-server-software-defined-networking-stack#check-for-corresponding-hostids-and-certificates-between-network-controller-and-each-hyper-v-host"
        }
    }
    ConfigurationStateErrorCodes = @{
        'Unknown' = @{
            Message = 'Unknown error'
            Action = 'Collect the logs and contact Microsoft Support'
        }
        'HostUnreachable' = @{
            Message = 'The host machine is not reachable'
            Action = 'Check the Management network connectivity between Network Controller and Host'
        }
        'PAIpAddressExhausted' = @{
            Message = 'The PA Ip addresses exhausted'
            Action = 'Increase the HNV Provider logical subnet''s IP Pool Size'
        }
        'PAMacAddressExhausted' = @{
            Message = 'The PA Mac addresses exhausted'
            Action = 'Increase the Mac Pool Range'
        }
        'PAAddressConfigurationFailure' = @{
            Message = 'Failed to plumb PA addresses to the host'
            Action = 'Check the management network connectivity between Network Controller and Host.'
        }
        'CertificateNotTrusted' = @{
            Message = 'Certificate is not trusted'
            Action = 'Fix the certificates used for communication with the host.'
        }
        'CertificateNotAuthorized' = @{
            Message = 'Certificate not authorized'
            Action = 'Fix the certificates used for communication with the host.'
        }
        'PolicyConfigurationFailureOnVfp' = @{
            Message = 'Failure in configuring VFP policies'
            Action = 'This is a runtime failure.  No definite workarounds. Collect logs.'
        }
        'HostNotConnectedToController' = @{
            Message = 'The Host is not yet connected to the Network Controller'
            Action = 'Validate that Host is online and operational, NCHostAgent service is started and HostID registry key matches the Instance ID of the server resource'
        }
        'MultipleVfpEnabledSwitches' = @{
            Message = 'There are multiple VFp enabled Switches on the host'
            Action = 'Delete one of the switches, since Network Controller Host Agent only supports one vSwitch with the VFP extension enabled'
        }
        'PolicyConfigurationFailure' = @{
            Message = 'Failed to push policies (vSwitch, vNet, ACL) for a VmNic due to certificate errors or connectivity errors'
            Action = 'Check if proper certificates have been deployed (Certificate subject name must match FQDN of host). Also verify the host connectivity with the Network Controller'
        }
        'DistributedRouterConfigurationFailure' = @{
            Message = 'Failed to configure the Distributed router settings on the host vNic'
            Action = 'TCPIP stack error. May require cleaning up the PA and DR Host vNICs on the server on which this error was reported'
        }
        'DhcpAddressAllocationFailure' = @{
            Message = 'DHCP address allocation failed for a VMNic'
            Action = 'Check if the static IP address attribute is configured on the NIC resource'
        }
        'CertificateNotTrusted CertificateNotAuthorized' = @{
            Message = 'Failed to connect to Mux due to network or cert errors'
            Action = 'Check the numeric code provided in the error message code: this corresponds to the winsock error code. Certificate errors are granular (for example, cert cannot be verified, cert not authorized, etc.)'
        }
        'PortBlocked' = @{
            Message = 'The VFP port is blocked, due to lack of VNET / ACL policies'
            Action = 'Check if there are any other errors, which might cause the policies to be not configured.'
        }
        'Overloaded' = @{
            Message = 'Loadbalancer MUX is overloaded'
            Action = 'Performance issue with MUX'
        }
        'RoutePublicationFailure' = @{
            Message = 'Loadbalancer MUX is not connected to a BGP router'
            Action = 'Check if the MUX has connectivity with the BGP routers and that BGP peering is setup correctly'
        }
        'VirtualServerUnreachable' = @{
            Message = 'Loadbalancer MUX is not connected to SLB manager'
            Action = 'Check connectivity between SLBM and MUX'
        }
        'QosConfigurationFailure' = @{
            Message = 'Failed to configure QOS policies'
            Action = 'See if sufficient bandwidth is available for all VM''s if QOS reservation is used'
        }
    }
}
