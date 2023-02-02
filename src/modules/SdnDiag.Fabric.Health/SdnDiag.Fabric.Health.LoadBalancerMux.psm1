# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-SdnLoadBalancerMuxConfigState {
    <#
    .SYNOPSIS
        Validate that the configurationState and provisioningState is Success
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
	.PARAMETER NcRestCredential
		Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    .EXAMPLE
        PS> Test-SdnLoadBalancerMuxConfigState
    .EXAMPLE
        PS> Test-SdnLoadBalancerMuxConfigState -NcRestCredential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Uri]$NcUri = $Global:SdnDiagnostics.EnvironmentInfo.NcUrl,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        "Validating configuration and provisioning state of Load Balancer Muxes" | Trace-Output

        if($null -eq $NcUri){
            throw New-Object System.NullReferenceException("Please specify NcUri parameter or execute Get-SdnInfrastructureInfo to populate environment details")
        }

        # if NcRestCredential parameter not defined, check to see if global cache is populated
        if(!$PSBoundParameters.ContainsKey('NcRestCredential')){
            if($Global:SdnDiagnostics.NcRestCredential){
                $NcRestCredential = $Global:SdnDiagnostics.NcRestCredential
            }
        }

        $status = 'Success'
        $arrayList = [System.Collections.ArrayList]::new()

        $muxes = Get-SdnLoadBalancerMux -NcUri $NcUri.AbsoluteUri -Credential $NcRestCredential
        foreach($object in $muxes){
            if($object.properties.configurationState.status -ine 'Success' -or $object.properties.provisioningState -ine 'Succeeded'){
                $status = 'Failure'

                $details = [PSCustomObject]@{
                    resourceRef = $object.resourceRef
                    provisioningState = $object.properties.provisioningState
                    configurationState = $object.properties.configurationState
                }

                [void]$arrayList.Add($details)

                "{0} is reporting configurationState status: {1} and provisioningState: {2}" `
                    -f $object.resourceRef, $object.properties.configurationState.Status, $object.properties.provisioningState | Trace-Output -Level:Warning
            }
            else {
                "{0} is reporting configurationState status: {1} and provisioningState: {2}" `
                    -f $object.resourceRef, $object.properties.configurationState.Status, $object.properties.provisioningState | Trace-Output -Level:Verbose
            }
        }

        return [PSCustomObject]@{
            Status = $status
            Properties = $arrayList
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Test-SdnLoadBalancerMuxServiceState {
    <#
    .SYNOPSIS
        Confirms that critical services for load balancer muxes are running
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Test-SdnLoadBalancerMuxServiceState
    .EXAMPLE
        PS> Test-SdnLoadBalancerMuxServiceState -ComputerName 'SLB01','SLB02'
    .EXAMPLE
        PS> Test-SdnLoadBalancerMuxServiceState -ComputerName 'SLB01','SLB02' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String[]]$ComputerName = $global:SdnDiagnostics.EnvironmentInfo.LoadBalancerMux,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $config = Get-SdnRoleConfiguration -Role:LoadBalancerMux
        "Validating that {0} service is running for {1} role" -f ($config.properties.services.properties.displayName -join ', '), $config.Name | Trace-Output

        if($null -eq $ComputerName){
            throw New-Object System.NullReferenceException("Please specify ComputerName parameter or execute Get-SdnInfrastructureInfo to populate environment details")
        }

        # if Credential parameter not defined, check to see if global cache is populated
        if(!$PSBoundParameters.ContainsKey('Credential')){
            if($Global:SdnDiagnostics.Credential){
                $Credential = $Global:SdnDiagnostics.Credential
            }
        }

        $status = 'Success'
        $arrayList = [System.Collections.ArrayList]::new()

        $scriptBlock = {
            $serviceArrayList = [System.Collections.ArrayList]::new()
            foreach($service in $($using:config.properties.services.name)){
                $result = Get-Service -Name $service -ErrorAction SilentlyContinue
                if($result){
                    [void]$serviceArrayList.Add($result)
                }
            }

            return $serviceArrayList
        }

        $serviceStateResults = Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -Scriptblock $scriptBlock
        foreach($result in $serviceStateResults){
            if($result.Status -ine 'Running'){
                [void]$arrayList.Add($result)
                $status = 'Failure'

                "{0} is {1} on {2}" -f $result.Name, $result.Status, $result.PSComputerName | Trace-Output -Level:Warning
            }
            else {
                "{0} is {1} on {2}" -f $result.Name, $result.Status, $result.PSComputerName | Trace-Output -Level:Verbose
            }
        }

        return [PSCustomObject]@{
            Status = $status
            Properties = $arrayList
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
