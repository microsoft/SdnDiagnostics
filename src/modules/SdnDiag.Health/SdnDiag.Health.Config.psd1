# Copyright='© Microsoft Corporation. All rights reserved.'
# Licensed under the MIT License.

@{
    HealthValidations = @{
        'Test-EncapOverhead' = @{
            Description = "EncapOverhead/JumboPacket is not configured properly on the Hyper-V Hosts"
            Impact = "Intermittent packet loss may occur under certain conditions when routing traffic within the logical network."
            PublicDocUrl = "https://learn.microsoft.com/en-us/windows-server/networking/sdn/troubleshoot/troubleshoot-windows-server-software-defined-networking-stack#check-mtu-and-jumbo-frame-support-on-hnv-provider-logical-network"
        }
        'Test-HostRootStoreNonRootCert' = @{
            Description = ""
            Impact = ""
            PublicDocUrl = ""
        }
        'Test-MuxBgpConnectionState' = @{
            Description = "One or more Load Balancer Muxes do not have an active BGP connection via TCP port 179 to the switch."
            Impact = "Public IP addresses may not be routable as Load Balancer Muxes are not advertising the public IP addresses to the switch."
            PublicDocUrl = "https://learn.microsoft.com/en-us/azure-stack/hci/manage/troubleshoot-software-load-balancer"
        }
        'Test-NetworkControllerCertCredential' = @{
            Description = "Network Controller does not have the x509 certificate installed for southbound device(s)."
            Impact = "Network Controller will have issues communicating with the southbound device(s)."
            PublicDocUrl = ""
        }
        'Test-NetworkInterfaceAPIDuplicateMacAddress' = @{
            Description = "Duplicate MAC address detected within the API."
            Impact = "Policy configuration failures may be reported by Network Controller when applying policies to the Hyper-v host. Network Interfaces reporting configurationState failure will not be routable."
            PublicDocUrl = ""
        }
        'Test-ProviderNetwork' = @{
            Description = "Logical network does not support VXLAN or NVGRE encapsulated traffic"
            Impact = "Intermittent packet loss may occur under certain conditions when routing traffic within the logical network."
            PublicDocUrl = "https://learn.microsoft.com/en-us/windows-server/networking/sdn/troubleshoot/troubleshoot-windows-server-software-defined-networking-stack#check-mtu-and-jumbo-frame-support-on-hnv-provider-logical-network"
        }
        'Test-ResourceConfigurationState' = @{
            Description = "Infrastructure resource is not in a healthy state."
            Impact = "SDN services and functionality will be impacted."
            PublicDocUrl = "https://learn.microsoft.com/en-us/windows-server/networking/sdn/troubleshoot/troubleshoot-windows-server-software-defined-networking-stack#hoster-validate-system-health"
        }
        'Test-ScheduledTaskEnabled' = @{
            Description = "Scheduled task is not enabled on the SDN infrastructure node(s)."
            Impact = "Unconstrained log files may grow and consume disk space."
            PublicDocUrl = ""
        }
        'Test-ServerHostId' = @{
            Description = "HostID is not configured properly on the Hyper-V Hosts"
            Impact = "Mismatch of HostId between Hyper-V host(s) and Network Controller will result in policy configuration failures."
            PublicDocUrl = "https://learn.microsoft.com/en-us/windows-server/networking/sdn/troubleshoot/troubleshoot-windows-server-software-defined-networking-stack#check-for-corresponding-hostids-and-certificates-between-network-controller-and-each-hyper-v-host"
        }
        'Test-ServiceFabricPartitionDatabaseSize' = @{
            Description = ""
            Impact = ""
            PublicDocUrl = ""
        }
        'Test-ServiceState' = @{
            Description = "Identified service is not running on the SDN infrastructure node(s)."
            Impact = "SDN services and functionality will be impacted without the service running."
            PublicDocUrl = ""
        }
        'Test-VfpDuplicatePort' = @{
            Description = "Duplicate MAC address detected within Virtual Filtering Platform (VFP)."
            Impact = "Policy configuration failures may be reported by Network Controller when applying policies to the Hyper-v host. In addition, network traffic may be impacted."
            PublicDocUrl = ""
        }
        'Test-VMNetAdapterDuplicateMacAddress' = @{
            Description = "Duplicate MAC address detected with the data plane on the Hyper-V host(s)."
            Impact = "Policy configuration failures may be reported by Network Controller when applying policies to the Hyper-v host. In addition, network traffic may be impacted for the interfaces that are duplicated."
            PublicDocUrl = ""
        }
    }
}
