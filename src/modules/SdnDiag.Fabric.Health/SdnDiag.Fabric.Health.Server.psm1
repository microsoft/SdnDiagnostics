# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-SdnEncapOverhead {
    <#
    .SYNOPSIS
        Retrieves the VMSwitch across servers in the dataplane to confirm that the network interfaces support EncapOverhead or JumboPackets
        and that the settings are configured as expected
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String[]]$ComputerName = $global:SdnDiagnostics.InfrastructureInfo.Server,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    [int]$encapOverheadExpectedValue = 160
    [int]$jumboPacketExpectedValue = 1674 # this is default 1514 MTU + 160 encap overhead

    try {
        "Validating the network interfaces across the SDN dataplane support Encap Overhead or Jumbo Packets" | Trace-Output

        if ($null -eq $ComputerName) {
            throw New-Object System.NullReferenceException("Please specify ComputerName parameter or execute Get-SdnInfrastructureInfo to populate environment details")
        }

        # if Credential parameter not defined, check to see if global cache is populated
        if (!$PSBoundParameters.ContainsKey('Credential')) {
            if ($Global:SdnDiagnostics.Credential) {
                $Credential = $Global:SdnDiagnostics.Credential
            }
        }

        $arrayList = [System.Collections.ArrayList]::new()
        $status = 'Success'

        $encapOverheadResults = Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -Scriptblock { Get-SdnNetAdapterEncapOverheadConfig }
        if ($null -eq $encapOverheadResults) {
            throw New-Object System.NullReferenceException("No encap overhead results found")
        }

        foreach ($object in ($encapOverheadResults | Group-Object -Property PSComputerName)) {
            foreach ($interface in $object.Group) {
                "[{0}] {1}" -f $object.Name, ($interface | Out-String -Width 4096) | Trace-Output -Level:Verbose

                if ($interface.EncapOverheadEnabled -eq $false -or $interface.EncapOverheadValue -lt $encapOverheadExpectedValue) {
                    "EncapOverhead settings for {0} on {1} are disabled or not configured correctly" -f $interface.NetworkInterface, $object.Name | Trace-Output -Level:Warning

                    if ($interface.JumboPacketEnabled -eq $false -or $interface.JumboPacketValue -lt $jumboPacketExpectedValue) {
                        "JumboPacket settings for {0} on {1} are disabled or not configured correctly" -f $interface.NetworkInterface, $object.Name | Trace-Output -Level:Warning
                        $status = 'Failure'

                        $interface | Add-Member -NotePropertyName "ComputerName" -NotePropertyValue $object.Name
                        [void]$arrayList.Add($interface)
                    }
                }
            }
        }

        return [PSCustomObject]@{
            Status     = $status
            Properties = $arrayList
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Test-SdnProviderNetwork {
    <#
    .SYNOPSIS
        Performs ICMP tests across the computers defined to confirm that jumbo packets are able to successfully traverse between the provider addresses on each host
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Test-SdnProviderNetwork
    .EXAMPLE
        PS> Test-SdnPRoviderNetwork -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String[]]$ComputerName = $global:SdnDiagnostics.InfrastructureInfo.Server,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        "Validating Provider Address network has connectivity across the SDN dataplane" | Trace-Output

        if ($null -eq $ComputerName) {
            throw New-Object System.NullReferenceException("Please specify ComputerName parameter or execute Get-SdnInfrastructureInfo to populate environment details")
        }

        # if Credential parameter not defined, check to see if global cache is populated
        if (!$PSBoundParameters.ContainsKey('Credential')) {
            if ($Global:SdnDiagnostics.Credential) {
                $Credential = $Global:SdnDiagnostics.Credential
            }
        }

        $arrayList = [System.Collections.ArrayList]::new()
        $status = 'Success'

        $providerAddresses = (Get-SdnProviderAddress -ComputerName $ComputerName -Credential $Credential).ProviderAddress
        if ($null -eq $providerAddresses) {
            "No provider addresses were found on the hosts specified. This may be expected if tenant workloads have not yet been deployed." | Trace-Output -Level:Warning
        }

        if ($providerAddresses) {
            $connectivityResults = Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -Scriptblock { Test-SdnProviderAddressConnectivity -ProviderAddress $using:providerAddresses }
            foreach ($computer in $connectivityResults | Group-Object PSComputerName) {
                foreach ($destinationAddress in $computer.Group) {
                    if ($destinationAddress.Status -ine 'Success') {
                        $status = 'Failure'

                        $jumboPacketResult = $destinationAddress | Where-Object { $_.BufferSize -gt 1472 }
                        $standardPacketResult = $destinationAddress | Where-Object { $_.BufferSize -le 1472 }

                        # if both jumbo and standard icmp tests fails, indicates a failure in the physical network
                        if ($jumboPacketResult.Status -ieq 'Failure' -and $standardPacketResult.Status -ieq 'Failure') {
                            "Cannot ping to {0} from {1} using {2}. Investigate the physical connection." `
                                -f $destinationAddress[0].DestinationAddress, $computer.Name, $destinationAddress[0].SourceAddress | Trace-Output -Level:Warning
                        }

                        # if standard MTU was success but jumbo MTU was failure, indication that jumbo packets or encap overhead has not been setup and configured
                        # either on the physical nic or within the physical switches between the provider addresses
                        if ($jumboPacketResult.Status -ieq 'Failure' -and $standardPacketResult.Status -ieq 'Success') {
                            "Cannot send jumbo packets to {0} from {1} using {2}. Physical switch ports or network interface may not be configured to support jumbo packets." `
                                -f $destinationAddress[0].DestinationAddress, $computer.Name, $destinationAddress[0].SourceAddress | Trace-Output -Level:Warning
                        }

                        $destinationAddress | Add-Member -NotePropertyName "ComputerName" -NotePropertyValue $computer.Name
                        [void]$arrayList.Add($destinationAddress)
                    }
                }
            }
        }

        return [PSCustomObject]@{
            Status     = $status
            Properties = $arrayList
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Test-SdnServerConfigState {
    <#
    .SYNOPSIS
        Validate that the configurationState and provisioningState is Success
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
	.PARAMETER NcRestCredential
		Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    .EXAMPLE
        PS> Test-SdnServerConfigState
    .EXAMPLE
        PS> Test-SdnServerConfigState -NcRestCredential (Get-Credential)
    .EXAMPLE
        PS> Test-SdnServerConfigState -NcUri "https://nc.contoso.com" -NcRestCredential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Uri]$NcUri = $global:SdnDiagnostics.InfrastructureInfo.NcUrl,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        "Validating configuration and provisioning state of Servers" | Trace-Output

        if ($null -eq $NcUri) {
            throw New-Object System.NullReferenceException("Please specify NcUri parameter or execute Get-SdnInfrastructureInfo to populate environment details")
        }

        # if NcRestCredential parameter not defined, check to see if global cache is populated
        if (!$PSBoundParameters.ContainsKey('NcRestCredential')) {
            if ($Global:SdnDiagnostics.NcRestCredential) {
                $NcRestCredential = $Global:SdnDiagnostics.NcRestCredential
            }
        }

        $status = 'Success'
        $arrayList = [System.Collections.ArrayList]::new()

        $servers = Get-SdnServer -NcUri $NcUri.AbsoluteUri -Credential $NcRestCredential
        foreach ($object in $servers) {
            if ($object.properties.configurationState.status -ine 'Success' -or $object.properties.provisioningState -ine 'Succeeded') {
                $status = 'Failure'

                $details = [PSCustomObject]@{
                    resourceRef        = $object.resourceRef
                    provisioningState  = $object.properties.provisioningState
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
            Status     = $status
            Properties = $arrayList
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Test-SdnServerServiceState {
    <#
    .SYNOPSIS
        Confirms that critical services for load balancer muxes are running
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Test-SdnServerServiceState
    .EXAMPLE
        PS> Test-SdnServerServiceState -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Test-SdnServerServiceState -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String[]]$ComputerName = $global:SdnDiagnostics.InfrastructureInfo.Server,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $config = Get-SdnRoleConfiguration -Role:Server
        "Validating that {0} service is running for {1} role" -f ($config.properties.services.properties.displayName -join ', '), $config.Name | Trace-Output

        if ($null -eq $ComputerName) {
            throw New-Object System.NullReferenceException("Please specify ComputerName parameter or execute Get-SdnInfrastructureInfo to populate environment details")
        }

        # if Credential parameter not defined, check to see if global cache is populated
        if (!$PSBoundParameters.ContainsKey('Credential')) {
            if ($Global:SdnDiagnostics.Credential) {
                $Credential = $Global:SdnDiagnostics.Credential
            }
        }

        $status = 'Success'
        $arrayList = [System.Collections.ArrayList]::new()

        $scriptBlock = {
            $serviceArrayList = [System.Collections.ArrayList]::new()
            foreach ($service in $($using:config.properties.services.name)) {
                $result = Get-Service -Name $service -ErrorAction SilentlyContinue
                if ($result) {
                    [void]$serviceArrayList.Add($result)
                }
            }

            return $serviceArrayList
        }

        $serviceStateResults = Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -Scriptblock $scriptBlock
        foreach ($result in $serviceStateResults) {
            if ($result.Status -ine 'Running') {
                [void]$arrayList.Add($result)
                $status = 'Failure'

                "{0} is {1} on {2}" -f $result.Name, $result.Status, $result.PSComputerName | Trace-Output -Level:Warning
            }
            else {
                "{0} is {1} on {2}" -f $result.Name, $result.Status, $result.PSComputerName | Trace-Output -Level:Verbose
            }
        }

        return [PSCustomObject]@{
            Status     = $status
            Properties = $arrayList
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
