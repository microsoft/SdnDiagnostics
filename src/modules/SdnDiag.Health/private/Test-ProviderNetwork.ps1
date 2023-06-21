function Test-ProviderNetwork {
    <#
    .SYNOPSIS
        Performs ICMP tests across the computers defined to confirm that jumbo packets are able to successfully traverse between the provider addresses on each host
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricHealthObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()
    $array = @()

    try {
        "Validating Provider Address network has connectivity across the SDN dataplane" | Trace-Output

        $providerAddresses = (Get-SdnProviderAddress -ComputerName $SdnEnvironmentObject.ComputerName -Credential $Credential).ProviderAddress
        if ($null -eq $providerAddresses){
            "No provider addresses were found on the hosts specified. This may be expected if tenant workloads have not yet been deployed." | Trace-Output -Level:Warning
        }

        if ($providerAddresses) {
            $connectivityResults = Invoke-PSRemoteCommand -ComputerName $SdnEnvironmentObject.ComputerName -Credential $Credential -Scriptblock {
                param([Parameter(Position = 0)][String[]]$param1)
                Test-SdnProviderAddressConnectivity -ProviderAddress $param1
            } -ArgumentList $providerAddresses

            foreach($computer in $connectivityResults | Group-Object PSComputerName){
                foreach($destinationAddress in $computer.Group){
                    $jumboPacketResult = $destinationAddress | Where-Object {$_.BufferSize -gt 1472}
                    $standardPacketResult = $destinationAddress | Where-Object {$_.BufferSize -le 1472}

                    if($destinationAddress.Status -ine 'Success'){
                        $sdnHealthObject.Result = 'FAIL'

                        # if both jumbo and standard icmp tests fails, indicates a failure in the physical network
                        if($jumboPacketResult.Status -ieq 'Failure' -and $standardPacketResult.Status -ieq 'Failure'){
                            $remediationMsg = "Ensure ICMP enabled on {0} and {1}. If issue persists, investigate physical network." -f $destinationAddress[0].DestinationAddress, $destinationAddress[0].SourceAddress
                            $sdnHealthObject.Remediation += $remediationMsg

                            "Cannot ping {0} from {1} ({2})." `
                            -f $destinationAddress[0].DestinationAddress, $computer.Name, $destinationAddress[0].SourceAddress | Trace-Output -Level:Exception
                        }

                        # if standard MTU was success but jumbo MTU was failure, indication that jumbo packets or encap overhead has not been setup and configured
                        # either on the physical nic or within the physical switches between the provider addresses
                        if($jumboPacketResult.Status -ieq 'Failure' -and $standardPacketResult.Status -ieq 'Success'){
                            $remediationMsg += "Ensure the physical network between {0} and {1} configured to support VXLAN or NVGRE encapsulated packets with minimum MTU of 1660." `
                            -f $destinationAddress[0].DestinationAddress, $destinationAddress[0].SourceAddress
                            $sdnHealthObject.Remediation += $remediationMsg

                            "Cannot send jumbo packets to {0} from {1} ({2})." `
                            -f $destinationAddress[0].DestinationAddress, $computer.Name, $destinationAddress[0].SourceAddress | Trace-Output -Level:Exception
                        }
                    }
                    else {
                        "Successfully sent jumbo packet to {0} from {1} ({2})" `
                        -f $destinationAddress[0].DestinationAddress, $computer.Name, $destinationAddress[0].SourceAddress | Trace-Output
                    }

                    $array += $destinationAddress
                }
            }
        }

        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
