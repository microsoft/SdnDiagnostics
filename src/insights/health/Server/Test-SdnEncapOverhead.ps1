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
        [System.String[]]$ComputerName = $global:SdnDiagnostics.EnvironmentInfo.Server,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    [int]$encapOverheadExpectedValue = 160
    [int]$jumboPacketExpectedValue = 1674 # this is default 1514 MTU + 160 encap overhead

    try {
        if($null -eq $ComputerName){
            throw New-Object System.NullReferenceException("Please specify ComputerName parameter or execute Get-SdnInfrastructureInfo to populate environment details")
        }

        # if Credential parameter not defined, check to see if global cache is populated
        if(!$PSBoundParameters.ContainsKey('Credential')){
            if($Global:SdnDiagnostics.Credential){
                $Credential = $Global:SdnDiagnostics.Credential
            }
        }

        $insight = Get-InsightDetail -Id '7d7b3c9b-b670-4d44-b970-4e2a64f7de50' -Type Health
        $insight.Description | Trace-Output

        $arrayList = [System.Collections.ArrayList]::new()

        $encapOverheadResults = Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -Scriptblock {Get-NetworkInterfaceEncapOverheadSetting}
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
                        $insight.Detected = $true

                        $interface | Add-Member -NotePropertyName "ComputerName" -NotePropertyValue $object.Name
                        [void]$arrayList.Add($interface)
                    }
                }
            }
        }

        if ($arrayList) {
            $insight.Property = $arrayList
        }

        Set-SdnDiagCache -Container 'Health' -Name $MyInvocation.MyCommand -Value $insight
        return $insight
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
