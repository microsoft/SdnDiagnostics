function Test-ProviderNetwork {
    <#
    .SYNOPSIS
        Performs ICMP tests across the computers defined to confirm that jumbo packets are able to successfully traverse between the provider addresses on each host
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Test-ProviderNetwork
    .EXAMPLE
        PS> Test-ProviderNetwork -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()
    $arrayList = [System.Collections.ArrayList]::new()

    try {
        "Validating Provider Address network has connectivity across the SDN dataplane" | Trace-Output

        $providerAddresses = (Get-SdnProviderAddress -ComputerName $ComputerName -Credential $Credential).ProviderAddress
        if ($null -eq $providerAddresses){
            "No provider addresses were found on the hosts specified. This may be expected if tenant workloads have not yet been deployed." | Trace-Output -Level:Warning
        }

        if ($providerAddresses) {
            $connectivityResults = Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -Scriptblock {
                param([Parameter(Position = 0)][String[]]$param1)
                Test-SdnProviderAddressConnectivity -ProviderAddress $param1
            } -ArgumentList $providerAddresses

            foreach($computer in $connectivityResults | Group-Object PSComputerName){
                foreach($destinationAddress in $computer.Group){
                    if($destinationAddress.Status -ine 'Success'){
                        $sdnHealthObject.Result = 'FAIL'

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
        }

        $sdnHealthObject.Properties = $arrayList
        return $sdnHealthObject
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
