function Get-VfpPortState {
    <#
    .SYNOPSIS
        Returns the current VFP port state for a particular port Id.
    .DESCRIPTION
        Executes 'vfpctrl.exe /get-port-state /port $port' to return back the current state of the port specified.
    .PARAMETER PortName
        The port name to return the state for.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [GUID]$PortName
    )

    $object = [VfpPortState]::new()

    $vfpPortState = vfpctrl.exe /get-port-state /port $PortName
    if([string]::IsNullOrEmpty($vfpPortState)) {
        "Unable to locate port {0} from vfpctrl`n{1}" -f $PortName, $_ | Trace-Output -Level:Warning
        return $null
    }

    foreach ($line in $vfpPortState) {
        # skip if the line is empty or null
        if([string]::IsNullOrEmpty($line)) {
            continue
        }

        # split the line by the colon and trim the spaces
        $subValue = $line.Split(':').Trim()
        if ($subValue.Count -eq 2) {

            # due to some errors observed in environments, we need to wrap the conversion in a try/catch block
            # that way we can continue processing the remaining properties and not fail the entire function
            try {
                $propertyName = $subValue[0].Trim()
                $propertyValue = [System.Convert]::ToBoolean($subValue[1].Trim())
            }
            catch {
                "Unable to process value {0} for {1}`r`n`t{2}" -f $subValue[1].Trim(), $propertyName, $_.Exception | Trace-Output -Level:Warning
                continue
            }

            switch ($propertyName) {
                # update the VfpPortState properties
                'Enabled' { $object.Enabled = $propertyValue }
                'Blocked' { $object.Blocked = $propertyValue }
                'BlockedOnRestore' { $object.BlockOnRestore = $propertyValue }
                'BlockedLayerCreation' { $object.BlockLayerCreation = $propertyValue }
                'DTLS Offload Enabled' { $object.DtlsOffloadEnabled = $propertyValue }
                'GFT Offload Enabled' { $object.GftOffloadEnabled = $propertyValue }
                'QoS Hardware Transmit Cap Offload Enabled' { $object.QosHardwareCapsEnabled = $propertyValue }
                'QoS Hardware Transmit Reservation Offload Enabled' { $object.QosHardwareReservationsEnabled = $propertyValue }
                'Preserving Vlan' { $object.PreserveVlan = $propertyValue }
                'VM Context Set' { $object.IsVmContextSet = $propertyValue }

                # update the OffLoadStateDetails properties
                'NVGRE LSO Offload Enabled' { $object.PortState.LsoV2Supported = $propertyValue}
                'NVGRE RSS Enabled' { $object.PortState.RssSupported = $propertyValue }
                'NVGRE Transmit Checksum Offload Enabled' { $object.PortState.TransmitChecksumOffloadSupported = $propertyValue }
                'NVGRE Receive Checksum Offload Enabled' { $object.PortState.ReceiveChecksumOffloadSupported = $propertyValue }
                'NVGRE VMQ Enabled' { $object.PortState.VmqSupported = $propertyValue }
                'VXLAN LSO Offload Enabled' { $object.PortState.LsoV2SupportedVxlan = $propertyValue }
                'VXLAN RSS Enabled' { $object.PortState.RssSupportedVxlan = $propertyValue }
                'VXLAN Transmit Checksum Offload Enabled' { $object.PortState.TransmitChecksumOffloadSupportedVxlan = $propertyValue }
                'VXLAN Receive Checksum Offload Enabled' { $object.PortState.ReceiveChecksumOffloadSupportedVxlan = $propertyValue }
                'VXLAN VMQ Enabled' { $object.PortState.VmqSupportedVxlan = $propertyValue }
                'Inner MAC VMQ Enabled' { $object.PortState.InnerMacVmqEnabled = $propertyValue }

                default {
                    $propertyName = $propertyName.Replace(' ','').Trim()

                    try {
                        $object.$propertyName = $propertyValue
                    }
                    catch {
                        "Unable to add {0} to object. Failing back to use NoteProperty." -f $propertyName | Trace-Output -Level:Warning
                        $object | Add-Member -MemberType NoteProperty -Name $propertyName -Value $propertyValue
                        continue
                    }
                }
            }
        }
        else {
            # if the line does not have key/value pairs, then continue to next line
            continue
        }
    }

    return $object
}
