function Get-SdnNetAdapterRdmaConfig {
    <#
    .SYNOPSIS
        Checks numerous settings within a network adapter to validate RDMA status.
    .PARAMETER InterfaceIndex
        Interface index of the adapter for which RDMA config is to be verified.
    .EXAMPLE
        PS> Get-SdnNetAdapterRdmaConfig -InterfaceIndex 25
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [uint32]$InterfaceIndex
    )

    try {
        [System.String]$adapterType = $null
        [bool]$rdmaEnabled = $false
        [bool]$maxQueueConfigIsValid = $false
        [bool]$smbInterfaceRdmaCapable = $false
        [bool]$qosEnabled = $false
        [bool]$qosOperationalFlowControlEnabled = $false

        $rdmaAdapter = Get-NetAdapter -InterfaceIndex $InterfaceIndex
        if ($null -eq $rdmaAdapter) {
            throw New-Object System.NullReferenceException("Adapter with interface index $InterfaceIndex was not found")
        }

        "Determining adapter type based on interface description '{0}'" -f $rdmaAdapter.InterfaceDescription | Trace-Output -Level:Verbose
        switch -Wildcard ($rdmaAdapter.InterfaceDescription) {
            'Hyper-V Virtual Ethernet Adapter*' {
                $adapterType = "vNIC"
            }

            'Microsoft Hyper-V Network Adapter*' {
                $adapterType = "vmNIC"
            }

            default {
                $adapterType = "pNIC"
            }
        }

        "Network adapter {0} (Name: {1}) is a {2}" -f $rdmaAdapter.InterfaceIndex, $rdmaAdapter.Name, $adapterType | Trace-Output -Level:Verbose

        $rdmaCapabilities = Get-NetAdapterRdma -InterfaceDescription $rdmaAdapter.InterfaceDescription
        if($null -eq $rdmaCapabilities -or $rdmaCapabilities.Enabled -ieq $false) {
            $rdmaEnabled = $false
            "Network adapter {0} is not enabled for RDMA" -f $rdmaAdapter.InterfaceIndex | Trace-Output -Level:Warning
        }
        else {
            $rdmaEnabled = $rdmaCapabilities.Enabled
        }

        if ($rdmaCapabilities.MaxQueuePairCount -eq 0 -or $rdmaCapabilities.MaxCompletionQueueCount -eq 0) {
            $maxQueueConfigIsValid = $false
            "RDMA capabilities for adapter {0} are not valid. MaxQueuePairCount and MaxCompletionQueueCount cannot be set to 0" -f $rdmaAdapter.InterfaceIndex | Trace-Output -Level:Warning
        }
        else {
            $maxQueueConfigIsValid = $true
        }

        $rdmaAdapterSmbClientNetworkInterface = Get-SmbClientNetworkInterface | Where-Object {$_.InterfaceIndex -ieq $InterfaceIndex}
        if ($null -eq $rdmaAdapterSmbClientNetworkInterface) {
            "No interfaces found within SMB Client Network Interfaces that match interface index {0}" -f $InterfaceIndex | Trace-Output -Level:Warning
        }
        else {
            if ($rdmaAdapterSmbClientNetworkInterface.RdmaCapable -eq $false) {
                $smbInterfaceRdmaCapable = $false
                "SMB did not detect network adapter {0} as RDMA capable. Make sure the adapter is bound to TCP/IP and not to other protocol like vmSwitch." -f $rdmaAdapter.InterfaceIndex | Trace-Output -Level:Warning
            }
            else {
                $smbInterfaceRdmaCapable = $true
            }
        }

        if ($adapterType -eq "vNIC") {
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

        if ($null -ne $rdmaAdapters -and $adapterType -ne "vmNIC") {
            "Checking if QoS/DCB/PFC are configured on each physical adapter(s)" | Trace-Output -Level:Verbose

            # set these values to $true as we are looping multiple interfaces
            # we want to ensure if one interface is false for either value, that the object is reset back to $false
            # this ensures we don't get a false positive if some interfaces are enabled vs others are disabled

            $qosEnabled = $true
            $qosOperationalFlowControlEnabled = $true

            foreach ($qosAdapter in $rdmaAdapters) {
                "Checking {0}" -f $qosAdapter.InterfaceDescription | Trace-Output -Level:Verbose
                $qos = Get-NetAdapterQos -Name $qosAdapter.Name

                "NetAdapterQos is currently set to {0}" -f $qos.Enabled | Trace-Output -Level:Verbose
                if ($qos.Enabled -eq $false) {
                    $qosEnabled = $false
                    "QoS is not enabled for adapter {0}. This is required for RDMA over Converged Ethernet (RoCE)." -f $qosAdapter.InterfaceDescription | Trace-Output -Level:Warning
                }

                "OperationalFlowControl is currently set to {0}" -f $qos.OperationalFlowControl | Trace-Output -Level:Verbose
                if ($qos.OperationalFlowControl -eq "All Priorities Disabled") {
                    $qosOperationalFlowControlEnabled = $false
                    "Flow control priorities are disabled for adapter {0}. This is required for RDMA over Converged Ethernet (RoCE)." -f $qosAdapter.InterfaceDescription | Trace-Output -Level:Warning
                }
            }
        }

        $object = [PSCustomObject]@{
            Name                                = $rdmaAdapter.Name
            InterfaceDescription                = $rdmaAdapter.InterfaceDescription
            InterfaceIndex                      = $InterfaceIndex
            AdapterType                         = $adapterType
            MaxQueueConfigIsValid               = $maxQueueConfigIsValid
            QoSEnabled                          = $qosEnabled
            QoSOperationalFlowControlEnabled    = $qosOperationalFlowControlEnabled
            RdmaEnabled                         = $rdmaEnabled
            SMBInterfaceRdmaCapable             = $smbInterfaceRdmaCapable
        }

        return $object
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
