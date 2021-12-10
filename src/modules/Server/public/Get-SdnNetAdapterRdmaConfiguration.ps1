function Get-SdnNetAdapterRdmaConfiguration {
    <#
    .SYNOPSIS
        Checks numerous settings within a network adapter to validate RDMA status.
    .PARAMETER InterfaceIndex
        Interface index of the adapter for which RDMA config is to be verified.
    .PARAMETER IsRoCE
        True if underlying fabric type is RoCE. False for iWarp or IB. If omitted, defaults to $true.
    .EXAMPLE
        PS> Get-SdnNetAdapterRdmaConfiguration -InterfaceIndex 25 -IsRoCE:$true
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [uint32]$InterfaceIndex,

        [Parameter(Mandatory = $false)]
        [bool]$IsRoCE = $true
    )

    try {
        [System.String]$adapterType = $null
        [bool]$rdmaEnabled = $false
        [bool]$maxQueueConfigIsValid = $false
        [bool]$smbInterfaceDetected = $false
        [bool]$smbInterfaceRdmaCapable = $false
        [bool]$qosEnabled = $false
        [bool]$qosOperationalFlowControlEnabled = $false
        [bool]$rdmaConfigurationIsValid = $false

        $rdmaAdapter = Get-NetAdapter -InterfaceIndex $InterfaceIndex
        if ($null -eq $rdmaAdapter) {
            throw New-Object System.NullReferenceException("Adapter with interface index $InterfaceIndex was not found")
        }

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

        "The adapter {0} is a {1}" -f $rdmaAdapter.Name, $adapterType | Trace-Output -Level:Verbose

        $rdmaCapabilities = Get-NetAdapterRdma -InterfaceDescription $rdmaAdapter.InterfaceDescription
        if($null -eq $rdmaCapabilities -or $rdmaCapabilities.Enabled -ieq $false) {
            $rdmaEnabled = $false
            "The adapter {0} is not enabled for RDMA" -f $rdmaAdapter.Name | Trace-Output -Level:Warning
        }
        else {
            $rdmaEnabled = $rdmaCapabilities.Enabled
        }

        if ($rdmaCapabilities.MaxQueuePairCount -eq 0 -or $rdmaCapabilities.MaxCompletionQueueCount -eq 0) {
            $maxQueueConfigIsValid = $false
            "RDMA capabilities for adapter {0} are not valid. MaxQueuePairCount and MaxCompletionQueueCount cannot be set to 0" -f $rdmaAdapter.Name | Trace-Output -Level:Warning
        }
        else {
            $maxQueueConfigIsValid = $true
        }

        $smbClientNetworkInterfaces = Get-SmbClientNetworkInterface
        if ($null -eq $smbClientNetworkInterfaces) {
            $smbInterfaceDetected = $false
            "No network interfaces detected by SMB" | Trace-Output -Level:Warning
        }
        else {
            $smbInterfaceDetected = $true

            foreach ($smbClientNetworkInterface in $smbClientNetworkInterfaces) {
                if ($smbClientNetworkInterface.InterfaceIndex -ieq $InterfaceIndex) {
                    $rdmaAdapterSmbClientNetworkInterface = $smbClientNetworkInterface
                    "Found adapter {0} with SMB Client Interfaces" -f $smbClientNetworkInterface.InterfaceDescription | Trace-Output -Level:Verbose

                    break
                }
            }

            if ($null -eq $rdmaAdapterSmbClientNetworkInterface) {
                $smbInterfaceDetected = $false
                "No network interfaces found by SMB for adapter {0}" -f $rdmaAdapter.Name | Trace-Output -Level:Warning
            }
            else {
                if ($rdmaAdapterSmbClientNetworkInterface.RdmaCapable -eq $false) {
                    $smbInterfaceRdmaCapable = $false
                    "SMB did not detect adapter {0} as RDMA capable. Make sure the adapter is bound to TCP/IP and not to other protocol like vmSwitch." -f $rdmaAdapter.Name | Trace-Output -Level:Warning
                }
                else {
                    $smbInterfaceRdmaCapable = $true
                }
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

        if ($IsRoCE -and $adapterType -ne "vmNIC") {
            "Checking if QoS/DCB/PFC is configured on each physical adapter(s)" | Trace-Output -Level:Verbose

            # set these values to $true as we are looping multiple interfaces
            # we want to ensure if one interface is false for either value, that the object is reset back to $false
            # this ensures we don't get a false positive if some interfaces are enabled vs others are disabled

            $qosEnabled = $true
            $qosOperationalFlowControlEnabled = $true

            foreach ($qosAdapter in $rdmaAdapters) {
                "Checking {0}" -f $qosAdapter.InterfaceDescription | Trace-Output -Level:Verbose
                $qos = Get-NetAdapterQos -Name $qosAdapter.Name
                if ($qos.Enabled -eq $false) {
                    $qosEnabled = $false
                    "QoS is not enabled for adapter {0}" -f $qosAdapter.InterfaceDescription | Trace-Output -Level:Warning
                }

                if ($qos.OperationalFlowControl -eq "All Priorities Disabled") {
                    $qosOperationalFlowControlEnabled = $false
                    "Flow control is not enabled for adapter {0}" -f $qosAdapter.InterfaceDescription | Trace-Output -Level:Warning
                }
            }
        }

        # if IsRoCE:$True then we need to ensure that qosEnabled and qosOperationalFlowControlEnabled have been set to $true in order
        # for the RDMA configuration to be valid. If IsRoCE:$false then we can skip these values.
        if ($IsRoCE) {
            if ($qosEnabled -and $qosOperationalFlowControlEnabled -and $rdmaEnabled -and $maxQueueConfigIsValid -and $smbInterfaceDetected -and $smbInterfaceRdmaCapable) {
                $rdmaConfigurationIsValid = $true
            }
        }
        else {
            if ($rdmaEnabled -and $maxQueueConfigIsValid -and $smbInterfaceDetected -and $smbInterfaceRdmaCapable) {
                $rdmaConfigurationIsValid = $true
            }
        }

        $object = [PSCustomObject]@{
            Name                                = $rdmaAdapter.Name
            InterfaceDescription                = $rdmaAdapter.InterfaceDescription
            AdapterType                         = $adapterType
            MaxQueueConfigIsValid               = $maxQueueConfigIsValid
            QoSEnabled                          = $qosEnabled
            QoSOperationalFlowControlEnabled    = $qosOperationalFlowControlEnabled
            RdmaConfigurationIsValid            = $rdmaConfigurationIsValid
            RdmaEnabled                         = $rdmaEnabled
            RdmaOverConvergedEthernet           = $IsRoCE
            SMBInterfaceDetected                = $smbInterfaceDetected
            SMBInterfaceRdmaCapable             = $smbInterfaceRdmaCapable
        }

        return $object
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
