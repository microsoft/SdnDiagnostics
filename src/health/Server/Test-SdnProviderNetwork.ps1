# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
        [System.String[]]$ComputerName = $global:SdnDiagnostics.EnvironmentInfo.Host,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        "Validating Provider Address network has connectivity across the SDN dataplane" | Trace-Output

        if($null -eq $ComputerName){
            throw New-Object System.NullReferenceException("Please specify ComputerName parameter or execute Get-SdnInfrastructureInfo to populate environment details")
        }

        # if Credential parameter not defined, check to see if global cache is populated
        if(!$PSBoundParameters.ContainsKey('Credential')){
            if($Global:SdnDiagnostics.Credential){
                $Credential = $Global:SdnDiagnostics.Credential
            }    
        }

        $arrayList = [System.Collections.ArrayList]::new()
        $status = 'Success'

        $providerAddresses = (Get-SdnProviderAddress -ComputerName $ComputerName -Credential $Credential).ProviderAddress
        $connectivityResults = Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -Scriptblock {Test-SdnProviderAddressConnectivity -ProviderAddress $using:providerAddresses}
        foreach($computer in $connectivityResults | Group-Object PSComputerName){
            foreach($destinationAddress in $computer.Group){
                if($destinationAddress.Status -ine 'Success'){
                    $status = 'Failure'

                    $jumboPacketResult = $destinationAddress | Where-Object {$_.BufferSize -gt 1472}
                    $standardPacketResult = $destinationAddress | Where-Object {$_.BufferSize -le 1472}

                    # if both jumbo and standard icmp tests fails, indicates a failure in the physical network
                    if($jumboPacketResult.Status -ieq 'Failure' -and $standardPacketResult.Status -ieq 'Failure'){
                        "Cannot ping to {0} from {1} using {2}. Investigate the physical connection." `
                            -f $destinationAddress[0].DestinationAddress, $computer.Name, $destinationAddress[0].SourceAddress | Trace-Output -Level:Warning
                    }

                    # if standard MTU was success but jumbo MTU was failure, indication that jumbo packets or encap overhead has not been setup and configured
                    # either on the physical nic or within the physical switches between the provider addresses
                    if($jumboPacketResult.Status -ieq 'Failure' -and $standardPacketResult.Status -ieq 'Success'){
                        "Cannot send jumbo packets to {0} from {1} using {2}. Physical switch ports or network interface may not be configured to support jumbo packets." `
                            -f $destinationAddress[0].DestinationAddress, $computer.Name, $destinationAddress[0].SourceAddress | Trace-Output -Level:Warning
                    }

                    $destinationAddress | Add-Member -NotePropertyName "ComputerName" -NotePropertyValue $computer.Name
                    [void]$arrayList.Add($destinationAddress)
                }
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