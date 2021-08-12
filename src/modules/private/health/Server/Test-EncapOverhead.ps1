function Test-EncapOverhead {
    <#
    .SYNOPSIS
        Retrieves the VMSwitch across servers in the dataplane to confirm that the network interfaces support EncapOverhead or JumboPackets
        and that the settings are configured as expected
    #>

    [int]$encapOverheadExpectedValue = 160 
    [int]$jumboPacketExpectedValue = 1674 # this is default 1514 MTU + 160 encap overhead

    try {
        "Validating the network interfaces across the SDN dataplane support Encap Overhead or Jumbo Packets" | Trace-Output

        $servers = $SdnDiagnostics.EnvironmentInfo.Host

        $credential = [System.Management.Automation.PSCredential]::Empty
        if($Global:SdnDiagnostics.Credential){
            $credential = $Global:SdnDiagnostics.Credential
        }

        $arrayList = [System.Collections.ArrayList]::new()
        $status = 'Success'

        $encapOverheadResults = Invoke-PSRemoteCommand -ComputerName $servers -Credential $credential -Scriptblock {Get-SdnNetworkInterfaceEncapOverheadSetting}
        foreach($object in ($encapOverheadResults | Group-Object -Property PSComputerName | Sort-Object -Unique)){
            foreach($interface in $object.Group){
                if($interface.EncapOverheadEnabled -eq $false -or $interface.EncapOverheadValue -lt $encapOverheadExpectedValue){
                    "EncapOverhead settings for {0} on {1} are disabled or not configured correctly" -f $interface.NetworkInterface, $object.Name | Trace-Output -Level:Warning

                    if($interface.JumboPacketEnabled -eq $false -or $interface.JumboPacketValue -lt $jumboPacketExpectedValue){
                        "JumboPacket settings for {0} on {1} are disabled or not configured correctly" -f $interface.NetworkInterface, $object.Name | Trace-Output -Level:Warning
                        $status = 'Failure'

                        $interface | Add-Member -NotePropertyName "ComputerName" -NotePropertyValue $object.Name
                        [void]$arrayList.Add($interface)
                    }
                }
                else {
                    continue
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