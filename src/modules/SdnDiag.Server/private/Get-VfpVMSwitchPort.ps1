function Get-VfpVMSwitchPort {
    <#
    .SYNOPSIS
        Returns a list of ports from within VFP.
    #>

    $arrayList = [System.Collections.ArrayList]::new()

    try {
        $vfpResults = vfpctrl /list-vmswitch-port
        if ($null -eq $vfpResults) {
            "Unable to retrieve vmswitch ports from vfpctrl`n{0}" -f $_ | Trace-Output -Level:Warning
            return $null
        }

        foreach ($line in $vfpResults) {
            $line = $line.Trim()

            if ([string]::IsNullOrEmpty($line)) {
                continue
            }

            # lines in the VFP output that contain : contain properties and values
            # need to split these based on count of ":" to build key and values
            # some values related to ingress packet drops have multiple ":" so need to account for that
            # example: {property} : {reason} : {value}
            # example: {property} : {value}
            if ($line.Contains(":")) {
                [System.String[]]$results = $line.Split(':').Trim()
                if ($results.Count -eq 3) {
                    $key    = $results[1].Replace(' ','').Trim() # we want the key to align with the {reason}
                    $value  = $results[2].Trim()

                    if ($results[0].Trim() -eq 'Ingress packet drops') {
                        $object.NicStatistics.IngressDropReason.$key = $value
                    }
                    elseif($results[0].Trim() -eq 'Egress packet drops') {
                        $object.NicStatistics.EgressDropReason.$key = $value
                    }
                }
                elseif ($results.Count -eq 2) {
                    $key    = $results[0].Trim() # we want the key to align with the {property}
                    $value  = $results[1].Trim()

                    switch ($key) {
                        # all ports start with the port name property
                        # so we will key off this property to know when to add the object to the array
                        # and to create a new object
                        'Port name' {
                            if ($object) {
                                [void]$arrayList.Add($object)
                            }

                            $object = [VfpVmSwitchPort]@{
                                PortName = $value
                            }

                            continue
                        }

                        "SR-IOV Weight" { $object.SRIOVWeight = $value }
                        "SR-IOV Usage" { $object.SRIOVUsage = $value }

                        # populate the NicStatistics object
                        'Bytes Sent' { $object.NicStatistics.BytesSent = $value }
                        'Bytes Received' { $object.NicStatistics.BytesReceived = $value }
                        'Ingress Packet Drops' { $object.NicStatistics.IngressPacketDrops = $value }
                        'Egress Packet Drops' { $object.NicStatistics.EgressPacketDrops = $value }
                        'Ingress VFP Drops' { $object.NicStatistics.IngressVfpDrops = $value }
                        'Egress VFP Drops' { $object.NicStatistics.EgressVfpDrops = $value }

                        # populate the VmNicStatistics object
                        'Packets Sent' { $object.VmNicStatistics.PacketsSent = $value }
                        'Packets Received' { $object.VmNicStatistics.PacketsReceived = $value }
                        'Interrupts Received' { $object.VmNicStatistics.InterruptsReceived = $value }
                        'Send Buffer Allocation Count' { $object.VmNicStatistics.SendBufferAllocationSize = $value }
                        'Send Buffer Allocation Size' { $object.VmNicStatistics.SendBufferAllocationSize = $value }
                        'Receive Buffer Allocation Count' { $object.VmNicStatistics.ReceiveBufferAllocationCount = $value }
                        'Receive Buffer Allocation Size' { $object.VmNicStatistics.ReceiveBufferAllocationSize = $value }
                        'Pending Link Change' { $object.VmNicStatistics.PendingLinkChange = $value }
                        'Ring Buffer Full Errors' { $object.VmNicStatistics.RingBufferFullErrors = $value }
                        'Pending Routed Packets' { $object.VmNicStatistics.PendingRoutedPackets = $value }
                        'Insufficient Receive Buffers' { $object.VmNicStatistics.InsufficientReceiveBuffers = $value }
                        'Insufficient Send Buffers' { $object.VmNicStatistics.InsufficientSendBuffers = $value }
                        'Insufficient RNDIS Operations Buffers' { $object.VmNicStatistics.InsufficientRndisOperationsBuffers = $value }
                        'Quota Exceeded Errors' { $object.VmNicStatistics.QuotaExceededErrors = $value }
                        'Vsp Paused' { $object.VmNicStatistics.VspPaused = $value }

                        # most of the property names, we can just trim and remove the white spaces
                        # which will align to the class property names
                        default {
                            try {
                                $object.$($key.Replace(' ','').Trim()) = $value
                            }
                            catch {
                                "Unable to add {0} to object`n{1}" -f $key, $_ | Trace-Output -Level:Warning
                            }
                        }
                    }
                }
            }
            else {
                switch -Wildcard ($line) {
                    "Port is*" { $object.PortState = $line.Split(' ')[2].Replace('.','').Trim() }
                    "MAC Learning is*" { $object.MacLearning = $line.Split(' ')[3].Replace('.','').Trim() }
                    "NIC is*" { $object.NicState = $line.Split(' ')[2].Replace('.','').Trim() }
                    "*list-vmswitch-port*" {
                        # we have reached the end of the file at this point
                        # and should add any remaining objects to the array
                        if ($object) {
                            [void]$arrayList.Add($object)
                        }
                    }
                    default {
                        # the line does not contain anything we looking for
                        # and we can skip it and proceed to next
                        continue
                    }
                }
            }
        }

        return $arrayList
    }
    catch {
        return $object
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
