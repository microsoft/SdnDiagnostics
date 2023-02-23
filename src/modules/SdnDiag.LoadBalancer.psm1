# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. "$PSScriptRoot\..\scripts\SdnDiag.Utilities.ps1"
Import-Module "$PSScriptRoot\SdnDiag.LoadBalancer.Mux.psm1"

function Get-PublicIpReference {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [uri]$NcUri,

        [Parameter(Mandatory = $true)]
        [System.Object]$IpConfiguration,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {

        # check for an instance-level public IP address that is directly associated
        # with the ipconfiguration and return back to calling function
        if ($IpConfiguration.properties.publicIPAddress) {
            "Located {0} associated with {1}" -f $IpConfiguration.properties.publicIPAddress.resourceRef, $IpConfiguration.resourceRef | Trace-Output -Level:Verbose
            return ($IpConfiguration.properties.publicIPAddress.resourceRef)
        }
        else {
            "Unable to locate an instance-level public IP address associated with {0}" -f $IpConfiguration.resourceRef | Trace-Output -Level:Verbose
        }

        # NIC is connected to a load balancer with public IP association
        # or NIC is not associated to a public IP by any means and instead is connected via implicit load balancer attached to a virtual network
        "Checking for any backend address pool associated with {0}" -f $IpConfiguration.resourceRef | Trace-Output -Level:Verbose
        if ($IpConfiguration.properties.loadBalancerBackendAddressPools) {
            "Located backend address pool associations for {0}" -f $IpConfiguration.resourceRef | Trace-Output -Level:Verbose
            $loadBalancers = Get-SdnResource -NcUri $NcUri.AbsoluteUri -Resource:LoadBalancers -Credential $Credential
            $allBackendPoolRefs = @($IpConfiguration.properties.loadBalancerBackendAddressPools.resourceRef)

            $backendHash = [System.Collections.Hashtable]::new()
            foreach ($group in $loadBalancers.properties.backendAddressPools | Group-Object resourceRef) {
                [void]$backendHash.Add($group.Name, $group.Group)
            }

            foreach ($backendPoolRef in $allBackendPoolRefs) {
                "Checking for outboundNatRules for {0}" -f $backendPoolRef | Trace-Output -Level:Verbose
                $bePool = $backendHash[$backendPoolRef]

                if ($bePool.properties.outboundNatRules) {
                    "Located outboundNatRule associated with {0}" -f $bePool.resourceRef | Trace-Output -Level:Verbose

                    $obRuleRef = $bePool.properties.outboundNatRules[0].resourceRef
                    break
                }
            }

            if ($obRuleRef) {
                $natRule = $loadBalancers.properties.outboundNatRules | Where-Object { $_.resourceRef -eq $obRuleRef }
                $frontendConfig = $loadBalancers.properties.frontendIPConfigurations | Where-Object { $_.resourceRef -eq $natRule.properties.frontendIPConfigurations[0].resourceRef }

                "Located {0} associated with {0}" -f $frontendConfig.resourceRef, $natRule.resourceRef | Trace-Output -Level:Verbose
                return ($frontendConfig.properties.publicIPAddress.resourceRef)
            }
            else {
                "Unable to locate outboundNatRules associated with {0}" -f $IpConfiguration.properties.loadBalancerBackendAddressPools.resourceRef | Trace-Output -Level:Verbose
            }
        }
        else {
            "Unable to locate any backend pools associated with {0}" -f $IpConfiguration.resourceRef | Trace-Output -Level:Verbose
        }

        return $null
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnNetworkInterfaceOutboundPublicIPAddress {
    <#
    .SYNOPSIS
        Gets the outbound public IP address that is used by a network interface.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER ResourceId
        Specifies the unique identifier for the networkinterface resource.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnNetworkInterfaceOutboundPublicIPAddress -NcUri "https://nc.contoso.com" -ResourceId '8f9faf0a-837b-43cd-b4bf-dbe996993514'
    .EXAMPLE
        PS> Get-SdnNetworkInterfaceOutboundPublicIPAddress -NcUri "https://nc.contoso.com" -ResourceId '8f9faf0a-837b-43cd-b4bf-dbe996993514' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [uri]$NcUri,

        [Parameter(Mandatory = $true)]
        [System.String]$ResourceId,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )
    try {
        $arrayList = [System.Collections.ArrayList]::new()

        $networkInterface = Get-SdnResource -NcUri $NcUri.AbsoluteUri -Resource:NetworkInterfaces -Credential $Credential | Where-Object { $_.resourceId -ieq $ResourceId }
        if ($null -eq $networkInterface) {
            throw New-Object System.NullReferenceException("Unable to locate network interface within Network Controller")
        }

        foreach ($ipConfig in $networkInterface.properties.ipConfigurations) {
            $publicIpRef = Get-PublicIpReference -NcUri $NcUri.AbsoluteUri -IpConfiguration $ipConfig -Credential $Credential
            if ($publicIpRef) {
                $publicIpAddress = Get-SdnResource -NcUri $NcUri.AbsoluteUri -Credential $Credential -ResourceRef $publicIpRef
                if ($publicIpAddress) {
                    [void]$arrayList.Add(
                        [PSCustomObject]@{
                            IPConfigResourceRef      = $ipConfig.resourceRef
                            IPConfigPrivateIPAddress = $ipConfig.properties.privateIPAddress
                            PublicIPResourceRef      = $publicIpAddress.resourceRef
                            PublicIPAddress          = $publicIpAddress.properties.ipAddress
                        }
                    )
                }
            }
        }

        return $arrayList
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnSlbStateInformation {
    <#
    .SYNOPSIS
        Generates an aggregated report of Virtual IPs (VIPs) in the environment and their current status as reported by the MUXes.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER ExecutionTimeout
        Specify the timeout duration to wait before automatically terminated. If omitted, defaults to 600 seconds.
    .PARAMETER PollingInterval
        Interval in which to query the state of the request to determine completion.
    .EXAMPLE
        Get-SdnSlbStateInformation -NcUri "https://nc.contoso.com"
    .EXAMPLE
        Get-SdnSlbStateInformation -NcUri "https://nc.contoso.com" -Credential (Get-Credential)
    .EXAMPLE
        Get-SdnSlbStateInformation -NcUri "https://nc.contoso.com" -ExecutionTimeout 1200
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [int]$ExecutionTimeOut = 600,

        [Parameter(Mandatory = $false)]
        [int]$PollingInterval = 5
    )

    try {
        [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri.AbsoluteUri -ResourceName 'SlbState'
        "Gathering SLB state information from {0}" -f $uri | Trace-Output -Level:Verbose

        $stopWatch = [system.diagnostics.stopwatch]::StartNew()

        $putResult = Invoke-WebRequestWithRetry -Method 'Put' -Uri $uri -Credential $Credential -Body "{}" -UseBasicParsing `
            -Content "application/json; charset=UTF-8" -Headers @{"Accept" = "application/json" }

        $resultObject = ConvertFrom-Json $putResult.Content
        "Response received $($putResult.Content)" | Trace-Output -Level:Verbose
        [System.String]$operationURI = Get-SdnApiEndpoint -NcUri $NcUri.AbsoluteUri -ResourceName 'SlbStateResults' -OperationId $resultObject.properties.operationId

        while ($true) {
            if ($stopWatch.Elapsed.TotalSeconds -gt $ExecutionTimeOut) {
                $msg = "Unable to get results for OperationId: {0}. Operation timed out" -f $operationId
                throw New-Object System.TimeoutException($msg)
            }

            Start-Sleep -Seconds $PollingInterval

            $stateResult = Invoke-WebRequestWithRetry -Uri $operationURI -UseBasicParsing -Credential $Credential
            $stateResult = $stateResult.Content | ConvertFrom-Json
            if ($stateResult.properties.provisioningState -ine 'Updating') {
                break
            }
        }

        $stopWatch.Stop()

        if ($stateResult.properties.provisioningState -ine 'Succeeded') {
            $msg = "Unable to get results for OperationId: {0}. {1}" -f $operationId, $stateResult.properties
            throw New-Object System.Exception($msg)
        }
        else {
            return $stateResult.properties.output
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
