function Test-EncapOverhead {
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
        [System.String[]]$ComputerName = $global:SdnDiagnostics.EnvironmentInfo.Server,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    [int]$encapOverheadExpectedValue = 160
    [int]$jumboPacketExpectedValue = 1674 # this is default 1514 MTU + 160 encap overhead
    $sdnHealthObject = [SdnHealth]::new()
    $sdnHealthObject.Result = 'PASS'
    $arrayList = [System.Collections.ArrayList]::new()

    try {
        "Validating the network interfaces across the SDN dataplane support Encap Overhead or Jumbo Packets" | Trace-Output

        $encapOverheadResults = Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -Scriptblock {Get-SdnNetAdapterEncapOverheadConfig}
        if($null -eq $encapOverheadResults){
            throw New-Object System.NullReferenceException("No encap overhead results found")
        }

        foreach($object in ($encapOverheadResults | Group-Object -Property PSComputerName)){
            foreach($interface in $object.Group){
                "[{0}] {1}" -f $object.Name, ($interface | Out-String -Width 4096) | Trace-Output -Level:Verbose

                if($interface.EncapOverheadEnabled -eq $false -or $interface.EncapOverheadValue -lt $encapOverheadExpectedValue){
                    "EncapOverhead settings for {0} on {1} are disabled or not configured correctly" -f $interface.NetworkInterface, $object.Name | Trace-Output -Level:Warning

                    if($interface.JumboPacketEnabled -eq $false -or $interface.JumboPacketValue -lt $jumboPacketExpectedValue){
                        "JumboPacket settings for {0} on {1} are disabled or not configured correctly" -f $interface.NetworkInterface, $object.Name | Trace-Output -Level:Warning
                        $sdnHealthObject.Result = 'FAIL'

                        $interface | Add-Member -NotePropertyName "ComputerName" -NotePropertyValue $object.Name
                        [void]$arrayList.Add($interface)
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
