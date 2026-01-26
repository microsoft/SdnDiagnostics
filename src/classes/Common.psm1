# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

##########################
#### CLASSES & ENUMS #####
##########################

class SdnFabricInfrastructure {
    [System.String[]]$NetworkController
    [System.String[]]$LoadBalancerMux
    [System.String[]]$Gateway
    [System.String[]]$Server
    [System.String]$NcUrl
    [System.String]$RestApiVersion
    [System.String[]]$FabricNodes
    [hashtable]$FailoverClusterConfig
    [System.String]$ClusterConfigType
}

# Export the class
Export-ModuleMember
