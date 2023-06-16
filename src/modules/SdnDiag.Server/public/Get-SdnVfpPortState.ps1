function Get-SdnVfpPortState {
    <#
    .SYNOPSIS
        Returns the current VFP port state for a particular port Id.
    .DESCRIPTION
        Executes 'vfpctrl.exe /get-port-state /port $port' to return back the current state of the port specified.
    .PARAMETER PortName
        The port name to return the state for.
    .EXAMPLE
        PS> Get-SdnVfpPortState -PortName 3DC59D2B-9BFE-4996-AEB6-2589BD20B559
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [GUID]$PortName
    )

    try {
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
                $propertyName = $subValue[0].Trim()
                $propertyValue = [System.Convert]::ToBoolean($subValue[1].Trim())

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
                        "Unable to parse {0}" -f $propertyName  | Trace-Output -Level:Warning
                    }
                }
            }
            else {
                continue
            }
        }

        return $object
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
