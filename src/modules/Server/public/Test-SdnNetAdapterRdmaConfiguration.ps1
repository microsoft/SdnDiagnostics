function Test-SdnNetAdapterRdmaConfiguration {
    <#
    .SYNOPSIS
        Checks numerous settings within a network adapter to validate RDMA status.
    .PARAMETER IfIndex
        Interface index of the adapter for which RDMA config is to be verified.
    .PARAMETER IsRoCE
        True if underlying fabric type is RoCE. False for iWarp or IB. If omitted, defaults to $true.
    .EXAMPLE
        PS> Test-SdnNetAdapterRdmaConfiguration -IfIndex 25 -IsRoCE:$true
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 1)]
        [System.UInt32] $IfIndex,

        [Parameter(Mandatory = $false, Position = 2)]
        [bool] $IsRoCE = $true
    )

    try {
        $rdmaConfiguration = [RDMAConfig]::new()

        $rdmaAdapter = Get-NetAdapter -IfIndex $IfIndex
        if ($null -eq $rdmaAdapter) {
            throw New-Object System.NullReferenceException("Adapter with interface index $IfIndex was not found")
        }

        $rdmaConfiguration.Name = $rdmaAdapter.Name
        $rdmaConfiguration.InterfaceDescription = $rdmaAdapter.InterfaceDescription

        switch -Wildcard ($rdmaConfiguration.InterfaceDescription) {
            'Hyper-V Virtual Ethernet Adapter*' {
                $rdmaConfiguration.AdapterType = "vNIC"
            }

            'Microsoft Hyper-V Network Adapter*' {
                $rdmaConfiguration.AdapterType = "vmNIC"
            }

            default {
                $rdmaConfiguration.AdapterType = "pNIC"
            }
        }

        "The adapter {0} is a {1}" -f $rdmaConfiguration.Name, $rdmaConfiguration.AdapterType | Trace-Output -Level:Verbose

        $rdmaCapabilities = Get-NetAdapterRdma -InterfaceDescription $rdmaAdapter.InterfaceDescription
        if($null -eq $rdmaCapabilities -or $rdmaCapabilities.Enabled -ieq $false) {
            $rdmaConfiguration.RdmaEnabled = $false
            "The adapter {0} is not enabled for RDMA" -f $rdmaConfiguration.Name | Trace-Output -Level:Warning
        }
        else {
            $rdmaConfiguration.RdmaEnabled = $rdmaCapabilities.Enabled
        }

        if ($rdmaCapabilities.MaxQueuePairCount -eq 0 -or $rdmaCapabilities.MaxCompletionQueueCount -eq 0) {
            $rdmaConfiguration.MaxQueueConfigIsValid = $false
            "RDMA capabilities for adapter {0} are not valid. MaxQueuePairCount and MaxCompletionQueueCount cannot be set to 0" -f $rdmaConfiguration.Name | Trace-Output -Level:Warning
        }
        else {
            $rdmaConfiguration.MaxQueueConfigIsValid = $true
        }

        $smbClientNetworkInterfaces = Get-SmbClientNetworkInterface
        if ($null -eq $smbClientNetworkInterfaces) {
            $rdmaConfiguration.SMBInterfaceDetected = $false
            "No network interfaces detected by SMB" | Trace-Output -Level:Warning
        }
        else {
            $rdmaConfiguration.SMBInterfaceDetected = $true

            foreach ($smbClientNetworkInterface in $smbClientNetworkInterfaces) {
                if ($smbClientNetworkInterface.InterfaceIndex -ieq $IfIndex) {
                    $rdmaAdapterSmbClientNetworkInterface = $smbClientNetworkInterface
                    "Found adapter {0} with SMB Client Interfaces" -f $smbClientNetworkInterface.InterfaceDescription | Trace-Output -Level:Verbose

                    break
                }
            }

            if ($null -eq $rdmaAdapterSmbClientNetworkInterface) {
                $rdmaConfiguration.SMBInterfaceDetected = $false
                "No network interfaces found by SMB for adapter {0}" -f $rdmaConfiguration.Name | Trace-Output -Level:Warning
            }
            else {
                if ($rdmaAdapterSmbClientNetworkInterface.RdmaCapable -eq $false) {
                    $rdmaConfiguration.SMBInterfaceRdmaCapable= $false
                    "SMB did not detect adapter {0} as RDMA capable. Make sure the adapter is bound to TCP/IP and not to other protocol like vmSwitch." -f $rdmaConfiguration.Name | Trace-Output -Level:Warning
                }
                else {
                    $rdmaConfiguration.SMBInterfaceRdmaCapable = $true
                }
            }
        }

        if ($rdmaConfiguration.AdapterType -eq "vNIC") {
            "Retrieving vSwitch bound to the virtual adapter" | Trace-Output -Level:Verbose
            $virtualAdapter = Get-VMNetworkAdapter -ManagementOS | Where-Object {$_.DeviceId -eq $rdmaAdapter.DeviceID}
            $vSwitch = Get-VMSwitch -Name $virtualAdapter.SwitchName
            if ($vSwitch) {
                "Found vSwitch: {0}" -f $vSwitch.Name | Trace-Output -Level:Verbose

                $rdmaAdapters = Get-NetAdapter -InterfaceDescription $vSwitch.NetAdapterInterfaceDescriptions
                if ($rdmaAdapters) {
                    "Found the following physical adapter(s) bound to vSwitch:`r`n`n {0}" -f `
                    ($rdmaAdapters.InterfaceDescription `
                    | Select-Object @{n="Description";e={"`t$($_)"}} `
                    | Select-Object -ExpandProperty Description `
                    | Out-String ) | Trace-Output -Level:Verbose
                }
            }
        }

        if ($IsRoCE -and $rdmaConfiguration.AdapterType -ne "vmNIC") {
            "Checking if QoS/DCB/PFC is configured on each physical adapter(s)" | Trace-Output -Level:Verbose

            # set these values to $true as we are looping multiple interfaces
            # we want to ensure if one interface is false for either value, that the object is reset back to $false
            # this ensures we don't get a false positive if some interfaces are enabled vs others are disabled

            $rdmaConfiguration.QoSEnabled = $true
            $rdmaConfiguration.QoSOperationalFlowControlEnabled = $true

            foreach ($qosAdapter in $rdmaAdapters) {
                "Checking {0}" -f $qosAdapter.InterfaceDescription | Trace-Output -Level:Verbose
                $qos = Get-NetAdapterQos -Name $qosAdapter.Name
                if ($qos.Enabled -eq $false) {
                    $rdmaConfiguration.QoSEnabled = $false
                    "QoS is not enabled for adapter {0}" -f $qosAdapter.InterfaceDescription | Trace-Output -Level:Warning
                }

                if ($qos.OperationalFlowControl -eq "All Priorities Disabled") {
                    $rdmaConfiguration.QoSOperationalFlowControlEnabled = $false
                    "Flow control is not enabled for adapter {0}" -f $qosAdapter.InterfaceDescription | Trace-Output -Level:Warning
                }
            }
        }

        $rdmaConfiguration.IsValid()

        return $rdmaConfiguration
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
