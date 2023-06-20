# Copyright='© Microsoft Corporation. All rights reserved.'
# Licensed under the MIT License.

@{
    HealthValidations = @{
        'Test-EncapOverhead' = @{
            Description = ""
            Impact = ""
            PublicDocUrl = ""
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
            Description = ""
            Impact = ""
            PublicDocUrl = ""
        }
        'Test-NetworkInterfaceAPIDuplicateMacAddress' = @{
            Description = "Duplicate MAC address detected within the API."
            Impact = "Policy configuration failures may be reported by Network Controller when applying policies to the Hyper-v host. Network Interfaces reporting configurationState failure will not be routable."
            PublicDocUrl = ""
        }
        'Test-ProviderNetwork' = @{
            Description = ""
            Impact = ""
            PublicDocUrl = ""
        }
        'Test-ResourceConfigurationState' = @{
            Description = ""
            Impact = ""
            PublicDocUrl = ""
        }
        'Test-ScheduledTaskEnabled' = @{
            Description = ""
            Impact = ""
            PublicDocUrl = ""
        }
        'Test-ServerHostId' = @{
            Description = ""
            Impact = ""
            PublicDocUrl = ""
        }
        'Test-ServiceFabricPartitionDatabaseSize' = @{
            Description = ""
            Impact = ""
            PublicDocUrl = ""
        }
        'Test-ServiceState' = @{
            Description = ""
            Impact = ""
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
