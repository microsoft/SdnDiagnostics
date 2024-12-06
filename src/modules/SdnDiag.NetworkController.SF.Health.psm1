# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

using module .\SdnDiag.Health.psm1

Import-Module $PSScriptRoot\SdnDiag.Health.psm1
Import-Module $PSScriptRoot\SdnDiag.Common.psm1
Import-Module $PSScriptRoot\SdnDiag.Utilities.psm1

##########################
#### CLASSES & ENUMS #####
##########################

##########################
####### FUNCTIONS ########
##########################

function Test-ServiceFabricApplicationHealth {
    <#
    .SYNOPSIS
        Validate the health of the Network Controller application within Service Fabric.
    #>

    [CmdletBinding()]
    param ()

    $sdnHealthObject = [SdnHealthTest]::new()

    try {
        $applicationHealth = Get-SdnServiceFabricApplicationHealth -ErrorAction Stop
        if ($applicationHealth.AggregatedHealthState -ine 'Ok') {
            $sdnHealthObject.Result = 'FAIL'
            $sdnHealthObject.Remediation += "Examine the Service Fabric Application Health for Network Controller to determine why the health is not OK."
        }
    }
    catch {
        $sdnHealthObject.Result = 'FAIL'
    }

    return $sdnHealthObject
}

function Test-ServiceFabricClusterHealth {
    <#
    .SYNOPSIS
        Validate the health of the Network Controller cluster within Service Fabric.
    #>

    [CmdletBinding()]
    param ()

    $sdnHealthObject = [SdnHealthTest]::new()

    try {
        $clusterHealth = Get-SdnServiceFabricClusterHealth -ErrorAction Stop
        if ($clusterHealth.AggregatedHealthState -ine 'Ok') {
            $sdnHealthObject.Result = 'FAIL'
            $sdnHealthObject.Remediation += "Examine the Service Fabric Cluster Health for Network Controller to determine why the health is not OK."
        }
    }
    catch {
        $sdnHealthObject.Result = 'FAIL'
    }

    return $sdnHealthObject
}

function Test-ServiceFabricNodeStatus {
    <#
    .SYNOPSIS
        Validate the health of the Network Controller nodes within Service Fabric.
    #>

    [CmdletBinding()]
    param ()

    $sdnHealthObject = [SdnHealthTest]::new()

    try {
        $ncNodes = Get-SdnServiceFabricNode -NodeName $env:COMPUTERNAME -ErrorAction Stop
        if ($null -eq $ncNodes) {
            $sdnHealthObject.Result = 'FAIL'
            return $sdnHealthObject
        }

        if ($ncNodes.NodeStatus -ine 'Up') {
            $sdnHealthObject.Result = 'FAIL'
            $sdnHealthObject.Remediation = 'Examine the Service Fabric Nodes for Network Controller to determine why the node is not Up.'
        }
    }
    catch {
        $sdnHealthObject.Result = 'FAIL'
    }

    return $sdnHealthObject
}
