function Test-EncapOverhead {
    <#
    .SYNOPSIS
        Retrieves the VMSwitch across servers in the dataplane to confirm that the network interfaces support EncapOverhead or JumboPackets
        and that the settings are configured as expected
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    [int]$encapOverheadExpectedValue = 160
    [int]$jumboPacketExpectedValue = 1674 # this is default 1514 MTU + 160 encap overhead
    $sdnHealthObject = [SdnHealth]::new()
    $array = @()

    try {
        "Validating the network interfaces across the SDN dataplane support Encap Overhead or Jumbo Packets" | Trace-Output

        $encapOverheadResults = Invoke-PSRemoteCommand -ComputerName $SdnEnvironmentObject.ComputerName -Credential $Credential -Scriptblock {Get-SdnNetAdapterEncapOverheadConfig}
        if($null -eq $encapOverheadResults){
            $sdnHealthObject.Result = 'FAIL'
        }
        else {
            foreach($object in ($encapOverheadResults | Group-Object -Property PSComputerName)){
                foreach($interface in $object.Group){
                    "[{0}] {1}" -f $object.Name, ($interface | Out-String -Width 4096) | Trace-Output -Level:Verbose

                    if($interface.EncapOverheadEnabled -eq $false -or $interface.EncapOverheadValue -lt $encapOverheadExpectedValue){
                        "EncapOverhead settings for {0} on {1} are disabled or not configured correctly" -f $interface.NetworkInterface, $object.Name | Trace-Output -Level:Verbose
                        $encapDisabled = $true
                    }

                    if($interface.JumboPacketEnabled -eq $false -or $interface.JumboPacketValue -lt $jumboPacketExpectedValue){
                        "JumboPacket settings for {0} on {1} are disabled or not configured correctly" -f $interface.NetworkInterface, $object.Name | Trace-Output -Level:Verbose
                        $jumboPacketDisabled = $true
                    }

                    # if both encapoverhead and jumbo packets are not set, this is indication the physical network cannot support VXLAN encapsulation
                    # and as such, environment would experience intermittent packet loss
                    if ($encapDisabled -and $jumboPacketDisabled) {
                        $sdnHealthObject.Result = 'FAIL'
                        $sdnHealthObject.Remediation += "Ensure EncapOverhead and JumboPacket for interface {0} on {1} are enabled and configured correctly." -f $interface.NetworkInterface, $object.Name

                        "EncapOverhead and JumboPacket for interface {0} on {1} are disabled or not configured correctly." -f $interface.NetworkInterface, $object.Name  | Trace-Output -Level:Error
                    }

                    $array += $interface
                }
            }

            $sdnHealthObject.Properties = $array
        }

        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
