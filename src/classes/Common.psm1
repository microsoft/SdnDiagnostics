# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

##########################
#### CLASSES & ENUMS #####
##########################

class SdnFabricInfrastructure {
    [System.String[]]$NetworkController
    [System.String[]]$LoadBalancerMux
    [System.String[]]$Gateway
    [System.String]$NcUrl
    [System.String]$RestApiVersion
    [System.String[]]$FabricNodes
}

# Export the class
Export-ModuleMember
