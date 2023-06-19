# Copyright='© Microsoft Corporation. All rights reserved.'
# Licensed under the MIT License.

@{
    HealthValidations = @{
        DuplicateMacAddressVfp = @{
            Description = "Duplicate MAC address detected within Virtual Filtering Platform (VFP)."
            Impact = "Policy configuration failures may be reported by Network Controller when applying policies to the Hyper-v host. In addition, network traffic may be impacted."
            Remediation = "Remove the offending network interface or adapter from the Hyper-v host."
        }
        DuplicateMacAddressApi = @{
            Description = "Duplicate MAC address detected within the API."
            Impact = "Policy configuration failures may be reported by Network Controller when applying policies to the Hyper-v host. Network Interfaces reporting configurationState failure will not be routable."
            Remediation = "Locate the offending Network Interface(s) within Network Controller and remove. Typically the Network Interface reporting configurationState success will be the valid Network Interface All remaining Network Interfaces should be removed or assigned new MAC address."
        }
        DuplicateMacAddress = @{
            Description = "Duplicate MAC address detected with the data plane on the Hyper-V host(s)."
            Impact = "Policy configuration failures may be reported by Network Controller when applying policies to the Hyper-v host. In addition, network traffic may be impacted for the interfaces that are duplicated."
            Remediation = "Remove the offending VM network adapter from Hyper-v host(s)."
        }
    }
}
