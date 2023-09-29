# --------------------------------------------------------------
#  Copyright © Microsoft Corporation.  All Rights Reserved.
#  Microsoft Corporation (or based on where you live, one of its affiliates) licenses this sample code for your internal testing purposes only.
#  Microsoft provides the following sample code AS IS without warranty of any kind. The sample code arenot supported under any Microsoft standard support program or services.
#  Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
#  The entire risk arising out of the use or performance of the sample code remains with you.
#  In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the code be liable for any damages whatsoever
#  (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss)
#  arising out of the use of or inability to use the sample code, even if Microsoft has been advised of the possibility of such damages.
# ---------------------------------------------------------------

# BGP-4 implementation

# RFCs:
#  RFC 4271 BGP-4
#  RFC 3392 Capabilities Advertisement with BGP-4
#  RFC 2918 Route Refresh for BGP-4

# Slightly implemented (extra data shouldn't break):
#  RFC 4760 Multiprotocol Extensions for BGP-4

# TODO:
#   Detect RAS BGP, temporarily disable with -force.

# Usage Examples:
#
# computer already has NIC:
#     Test-SdnExpressBGP -RouterIPAddress 10.10.182.3 -LocalIPAddress 10.10.182.7 -LocalASN 64628 -verbose -ComputerName sa18n22mux02
# computer does not have NIC:
#       $h = New-SdnExpressBGPHost -computername sa18n22-2 -localipaddress "10.10.182.20" -prefixlength 26 -vlanid 11
#       $h | Test-SdnExpressBGP -RouterIPAddress "10.10.182.3" -LocalASN 64628
#       $h | Remove-SdnExpressBGPHost

function GetBGPPathAttributeType {
    param(
        [int] $code
    )
    if ($code -lt $BGP_PATH_ATTRIBUTE_TYPES.count) {
        return $BGP_PATH_ATTRIBUTE_TYPES[$code]
    }
    else {
        return "$code"
    }
}

function CapabilityCodeLookup {
    param(
        [int] $code
    )
    switch ($code) {
        0 { return "Reserved" }
        1 { return "Multiprotocol Extensions for BGP-4" }
        2 { return "Route Refresh Capability for BGP-4" }
        3 { return "Outbound Route Filtering Capability" }
        4 { return "Multiple routes to a destination capability (deprecated)" }
        5 { return "Extended Next Hop Encoding" }
        6 { return "BGP Extended Message" }
        7 { return "BGPsec Capability" }
        8 { return "Multiple Labels Capability" }
        9 { return "BGP Role (TEMPORARY)" }
        { $_ -in 10..63 } { return "Unassigned" }
        64 { return "Graceful Restart Capability" }
        65 { return "Support for 4-octet AS number capability" }
        66 { return "Deprecated" }
        67 { return "Support for Dynamic Capability (capability specific)" }
        68 { return "Multisession BGP Capability" }
        69 { return "ADD-PATH Capability" }
        70 { return "Enhanced Route Refresh Capability" }
        71 { return "Long-Lived Graceful Restart (LLGR) Capability" }
        72 { return "Routing Policy Distribution" }
        73 { return "FQDN Capability" }
        { $_ -in 74..127 } { return "Unassigned" }
        128 { return "Prestandard Route Refresh (deprecated)" }
        129 { return "Prestandard Outbound Route Filtering (deprecated)" }
        130 { return "Prestandard Outbound Route Filtering (deprecated)" }
        131 { return "Prestandard Multisession (deprecated)" }
        { $_ -in 132..183 } { return "Unassigned" }
        184 { return "Prestandard FQDN (deprecated)" }
        185 { return "Prestandard OPERATIONAL message (deprecated)" }
        { $_ -in 186..238 } { return "Unassigned" }
        { $_ -in 239..254 } { return "Reserved for Experimental Use" }
        255 { return "Reserved" }
    }

}

function GetBytes {
    param(
        [byte[]] $bytes,
        [int] $offset,
        [int] $count
    )
    return $bytes[$offset..($offset + $count - 1)]
}
function GetInt32 {
    param(
        [byte[]] $bytes,
        [int] $offset
    )
    return [System.Int64]($bytes[$offset] * [Math]::pow(2, 24)) + ($bytes[$offset + 1] * [Math]::pow(2, 16)) + ($bytes[$offset + 2] * [Math]::pow(2, 8)) + $bytes[$offset + 3]
}

function GetInt16 {
    param(
        [byte[]] $bytes,
        [int] $offset
    )
    return [Int]($bytes[$offset] * 256) + $bytes[$offset + 1]
}
function GetInt8 {
    param(
        [byte[]] $bytes,
        [int] $offset
    )
    return [Int]$bytes[$offset]
}
function SetInt8 {
    param(
        [byte[]] $bytes,
        [int] $offset,
        [int] $value
    )
    $bytes[$offset] = $value
    return $bytes
}
function SetInt16 {
    param(
        [byte[]] $bytes,
        [int] $offset,
        [int] $value
    )
    $bytes[$offset] = [byte](($value -shr 8) -band [Byte] 0xFF)
    $bytes[$offset + 1] = [byte]( $value -band [Byte] 0xFF)
    return $bytes
}
function SetInt32 {
    param(
        [byte[]] $bytes,
        [int] $offset,
        [int] $value
    )
    $bytes[$offset] = $value -band 0xFF
    $bytes[$offset + 1] = ($value -shr 8) -band 0xFF
    $bytes[$offset + 2] = ($value -shr 16) -band 0xFF
    $bytes[$offset + 3] = ($value -shr 24) -band 0xFF
    return $bytes
}
function AddInt8 {
    param(
        [byte[]] $bytes,
        [int] $value
    )
    $bytes += [byte] $value
    return $bytes
}
function AddInt16 {
    param(
        [byte[]] $bytes,
        [int] $value
    )
    $bytes += [byte] (($value -shr 8) -band [byte] 0xFF)
    $bytes += [byte] ($value -band [byte] 0xFF)
    return $bytes
}
function AddInt32 {
    param(
        [byte[]] $bytes,
        [System.Int64] $value
    )
    $bytes += [byte]($value -band [byte]0xFF)
    $bytes += [byte](($value -shr 8) -band [byte]0xFF)
    $bytes += [byte](($value -shr 16) -band [byte]0xFF)
    $bytes += [byte](($value -shr 24) -band [byte]0xFF)
    return $bytes
}
function Get-BGPHeader {
    param(
        [byte[]] $bytes
    )
    $header = @{}
    $header.Marker = GetBytes $bytes $BGP_HEADER_MARKER_OFFSET 16
    $header.Length = GetInt16 $bytes $BGP_HEADER_LENGTH_OFFSET
    $header.Type = $BGP_TYPES[(GetInt8 $bytes $BGP_HEADER_TYPE_OFFSET)]
    return $header

}
function New-BGPOpen {

    [byte[]] $bytes = @()
    for ($i = 0; $i -lt 16; $i++) {
        $bytes += [byte] 0xFF
    }
    $bytes = AddInt16 $bytes 0
    $bytes = AddInt8 $bytes 1  #OPEN
    $bytes = AddInt8 $bytes 4
    $bytes = AddInt16 $bytes $LocalASN  #64628
    $bytes = AddInt16 $bytes 180
    $bytes = AddInt32 $bytes (([IPAddress] $localIPAddress).Address)

    #Uncomment if no optional params:
    #$bytes = AddInt8 $bytes 0

    #opt parms - hardcoded for now to include:

    $bytes = AddInt8 $bytes 12 #opt params len
    $bytes = AddInt8 $bytes 2  #type: capability code
    $bytes = AddInt8 $bytes 10 #len

    #  1   - Multiprotocol extensions for BGP-4: 0101
    $bytes = AddInt8 $bytes 1  #capability code
    $bytes = AddInt8 $bytes 4  #len
    $bytes = AddInt8 $bytes 0
    $bytes = AddInt8 $bytes 1
    $bytes = AddInt8 $bytes 0
    $bytes = AddInt8 $bytes 1

    #  2   - Route Refresh Capability for BGP-4
    $bytes = AddInt8 $bytes 2  #capability code
    $bytes = AddInt8 $bytes 0  #len

    #  128 - Prestandard Route Refresh (deprecated)
    $bytes = AddInt8 $bytes 128  #capability code
    $bytes = AddInt8 $bytes 0    #len

    $bytes = SetInt16 $bytes $BGP_HEADER_LENGTH_OFFSET (29 + (GetInt8 $bytes $BGP_OPEN_OPTPARMLEN_OFFSET))
    return $bytes
}
function New-BGPKeepalive {

    [byte[]] $bytes = @()
    for ($i = 0; $i -lt 16; $i++) {
        $bytes += [byte] 0xFF
    }
    $bytes = AddInt16 $bytes 19
    $bytes = AddInt8 $bytes 4  #KEEPALIVE

    return $bytes
}


function Get-BGPUpdate {
    param(
        [byte[]] $bytes
    )
    $update = @{}

    $TotalLen = GetInt16 $bytes $BGP_HEADER_LENGTH_OFFSET

    $WithdrawnRoutesLen = GetInt16 $bytes $BGP_UPDATE_WITHDRAWN_OFFSET
    $PathAttributesLen = GetInt16 $bytes ($BGP_UPDATE_WITHDRAWN_OFFSET + $withdrawnRoutesLen + 2)
    $NetworkLayerLen = $TotalLen - 23 - $PathAttributesLen - $WithdrawnRoutesLen

    $WithdrawnRoutesStart = $BGP_UPDATE_WITHDRAWN_OFFSET
    $PathAttributesStart = $WithdrawnRoutesStart + 2 + $WithdrawnRoutesLen
    $NetworkLayerStart = $PathAttributesStart + 2 + $PathAttributesLen

    Write-Verbose "Total length: $TotalLen"
    Write-Verbose "Withdrawn routes start: $WithdrawnRoutesStart"
    Write-Verbose "Withdrawn routes len: $WithdrawnRoutesLen"
    Write-Verbose "Path Attributes start: $PathAttributesStart"
    Write-Verbose "Path Attributes  len: $PathAttributesLen"
    Write-Verbose "Network Layer start: $NetworkLayerStart"
    Write-Verbose "Network Layer len: $NetworkLayerLen"

    Write-Verbose "Parsing Withdrawn Routes"
    $update.WithdrawnRoutes = @()
    $index = $WithdrawnRoutesStart + 2
    while ($index -lt $PathAttributesStart) {
        $PrefixBits = GetInt8 $bytes $index
        $PrefixBytes = [math]::ceiling($PrefixBits / 8)

        if ($PrefixBytes -gt 0) {
            $subnetBytes = GetBytes $bytes ($index + 1) $PrefixBytes
            for ($i = $PrefixBytes; $i -lt 4; $i++) {
                $subnetBytes += 0
            }
            $subnet = ([ipaddress] [byte[]]$subnetBytes).ipaddresstostring
            $update.WithdrawnRoutes += "$subnet/$prefixBits"
        }
        else {
            $update.WithdrawnRoutes += "0.0.0.0/0"
        }

        $index += $PrefixBytes + 1
    }

    Write-Verbose "Parsing Path Attributes"
    $update.PathAttributes = @()
    $index = $PathAttributesStart + 2
    while ($index -lt $NetworkLayerStart) {
        $PA = @{}
        $AttrFlags = GetInt8 $bytes ($index)
        $PA.Optional = [bool]($AttrFlags -band 128)
        $PA.Transitive = [bool]($AttrFlags -band 64)
        $PA.Partial = [bool]($AttrFlags -band 32)
        $PA.ExtendedLength = [bool]($AttrFlags -band 16)

        $PA.AttrType = GetBGPPathAttributeType(GetInt8 $bytes ($index + 1))

        if ($PA.ExtendedLength) {
            $AttrLen = GetInt16 $bytes ($index + 2)
            $AttrLenLen = 2
        }
        else {
            $AttrLen = GetInt8 $bytes ($index + 2)
            $AttrLenLen = 1
        }

        switch ($PA.AttrType) {
            "ORIGIN" {
                $PA.Value = $BGP_PATH_ATTRIBUTE_ORIGIN_VALUE[(GetInt8 $bytes ($index + 2 + $AttrLenLen))]
            }
            "AS_PATH" {
                $PA.ASPath = @()
                $pathindex = 0
                while ($pathindex -lt $AttrLen) {
                    $AttrValue = @{}
                    $AttrValue.PathSegmentType = $BGP_PATH_ATTRIBUTE_AS_PATH_SEGMENT_TYPE[(GetInt8 $bytes ($index + $pathindex + 2 + $AttrLenLen))]
                    $ASPaths = GetInt8 $bytes ($index + $pathindex + 4)
                    $ASIndex = 0
                    $AttrValue.ASes = @()
                    while ($ASIndex -lt $ASPaths) {
                        $AttrValue.ASes += GetInt16 $bytes ($index + $pathindex + 4 + $AttrLenLen + $ASIndex * 2)
                        $ASIndex += 1
                    }
                    $PA.ASPath += $AttrValue
                    $PathIndex += 2 + $ASPaths * 2
                }
                #<path segment type (1oct), path segment length (1oct), path segment value>
                #types: 1 AS_SET, 2 AS_SEQUENCE
                #value: set of ASes (Int16 ea)
            }
            "NEXT_HOP" {
                $PA.NextHop = ([ipaddress] (GetInt32 $bytes ($index + 2 + $AttrLenLen))).ipaddresstostring
            }
            { $_ -in "MULTI_EXIT_DISC", "LOCAL_PREF" } {
                $PA.Value = (GetInt32 $bytes ($index + 2 + $AttrLenLen))
            }
            "ATOMIC_AGGREGATE" {
                #Intentionally blank, no Attr Value
            }
            "AGGREGATOR" {
                $PA.AS = (GetInt16 $bytes ($index + 2 + $AttrLenLen))
                $PA.IPAddress = ([ipaddress] (GetInt32 $bytes ($index + 4 + $AttrLenLen))).ipaddresstostring
            }
            default {
                $PA.AttrValue = GetBytes $Bytes ($index + 2 + $AttrLenLen) $AttrLen
            }
        }

        $update.PathAttributes += $PA
        $index += $AttrLen + 2 + $AttrLenLen
    }

    Write-Verbose "Parsing Network Layer Reachability"

    $update.Prefixes = @()
    $index = $NetworkLayerStart

    while ($index -lt $TotalLen) {
        $PrefixBits = GetInt8 $bytes $index
        $PrefixBytes = [math]::ceiling($PrefixBits / 8)

        if ($PrefixBytes -gt 0) {
            $subnetBytes = GetBytes $bytes ($index + 1) $PrefixBytes
            for ($i = $PrefixBytes; $i -lt 4; $i++) {
                $subnetBytes += 0
            }
            $subnet = ([ipaddress] [byte[]]$subnetBytes).ipaddresstostring
            $update.Prefixes += "$subnet/$prefixBits"
        }
        else {
            $update.Prefixes += "0.0.0.0/0"
        }
        $Index += $PrefixBytes + 1
    }

    return $update
}

function Get-BGPOpen {
    param(
        [byte[]] $bytes
    )
    $open = @{}
    $open.Version = GetInt8 $bytes $BGP_OPEN_VERSION_OFFSET
    $open.AS = GetInt16 $bytes $BGP_OPEN_AS_OFFSET
    $open.HoldTime = GetInt16 $bytes $BGP_OPEN_HOLDTIME_OFFSET
    $open.BGPID = ([ipaddress] (GetInt32 $bytes $BGP_OPEN_BGPID_OFFSET)).ipaddresstostring
    $OptParmLen = GetInt8 $bytes $BGP_OPEN_OPTPARMLEN_OFFSET
    if ($optParmLen -gt 0) {
        $OptParms = GetBytes $bytes $BGP_OPEN_OPTPARM_OFFSET $OptParmLen
        $open.OptParams = @()
        $index = 0

        while ($index -lt $OptParmLen) {
            $newparam = @{}
            $newparamType = GetInt8 $OptParms ($index)
            $newparam.Type = $BGP_OPEN_OPTPARAM_TYPES[$newparamType]
            $newparamLength = GetInt8 $OptParms ($index + 1)
            $ParmValue = GetBytes $OptParms ($index + 2) ($newparamLength)
            $newparam.values = @()
            if ($newparamType -eq 2) {
                $capindex = 0
                while ($capindex -lt $newparamlength) {
                    $newcap = @{}
                    $newcap.Code = CapabilityCodeLookup (GetInt8 $ParmValue ($capindex))
                    $newcapLength = GetInt8 $ParmValue ($capindex + 1)
                    if ($newcaplength -gt 0) {
                        $newcap.value = GetBytes $ParmValue ($capindex + 2) ($newcaplength)
                    }
                    $newparam.values += $newcap
                    $capindex += $newcapLength + 2
                }
            }
            $open.OptParams += $newparam
            $index += $newparamLength + 2
        }
    }
    return $open
}

function Get-BGPNotification {
    param(
        [byte[]] $bytes
    )
    $notification = @{}
    $notification.ErrorCode = $BGP_ERROR_CODES[(GetInt8 $bytes $BGP_NOTIFICATION_CODE_OFFSET)]
    if ((GetInt8 $bytes $BGP_NOTIFICATION_CODE_OFFSET) -eq 1) {
        #Message
        $notification.ErrorSubcode = $BGP_ERROR_SUBCODE_MESSAGE[(GetInt8 $bytes $BGP_NOTIFICATION_SUBCODE_OFFSET)]
    }
    elseif ((GetInt8 $bytes $BGP_NOTIFICATION_CODE_OFFSET) -eq 2) {
        #OPEN
        $notification.ErrorSubcode = $BGP_ERROR_SUBCODE_OPEN[(GetInt8 $bytes $BGP_NOTIFICATION_SUBCODE_OFFSET)]
    }
    elseif ((GetInt8 $bytes $BGP_NOTIFICATION_CODE_OFFSET) -eq 6) {
        #CEASE
        $notification.ErrorSubcode = $BGP_ERROR_SUBCODE_CEASE[(GetInt8 $bytes $BGP_NOTIFICATION_SUBCODE_OFFSET)]
    }
    else {
        $notification.ErrorSubcode = GetInt8 $bytes $BGP_NOTIFICATION_SUBCODE_OFFSET
    }
    $notification.Data = GetInt16 $bytes $BGP_NOTIFICATION_DATA_OFFSET ((GetInt16 $bytes $BGP_HEADER_LENGTH_OFFSET) - 21)


    return $notification
}


function Set-BGPState {
    param(
        [BGPState] $State
    )

    Write-Verbose "BGP state change from $($Script:BGPState) to $State"
    $Script:bgpState = $State
}

function Get-BGPState {
    return $Script:bgpState
}


enum BGPOptParamType {
    Authentication
    Capabilities
}

enum BGPState {
    Idle
    Connect
    Active
    OpenSent
    OpenConfirm
    Established
    Custom
}

enum BGPOrigin {
    EGP
    IGP
    Incomplete
}

class BGPCapability {
    [String] $Code
    [byte[]] $Value
    [string]ToString() {
        return ($this.code)
    }
}
class BGPOptParam {
    [BGPOptParamType] $Type
    [BGPCapability[]] $Capabilities
    [string]ToString() {
        return ($this.type)
    }
}

class BGPPath {
    [string] $prefix
    [string] $NextHop
    [Int32[]] $Path
    [String] $LocPrf
    [Int32] $Metric
    [BGPOrigin] $Origin
    [string]ToString() {
        return ($this.prefix)
    }
}

class BGPPeer {
    [string] $LocalIPAddress
    [int32] $LocalAS
    [string] $RouterIPAddress
    [int32] $RouterAS
    [int16] $HoldTime
    [int16] $Version
    [string] $BGPID
    [BGPState] $State
    [BGPOptParam[]] $OptParams
    [BGPPath[]] $Routes
}

class BGPHost {
    [string] $ComputerName
    [string] $LocalIPAddress
}

function New-SdnExpressBGPHost {
    [CmdletBinding()]
    param(
        [String] $ComputerName = "localhost",
        [string] $SwitchName = "",
        [String] $LocalIPAddress,
        [Int32] $PrefixLength,
        [Int32] $VLANID = 0
    )

    #TODO: remember gateway parameter and during test add /32 route only if needed
    #TODO: test for hyper-v and Hyper-v powershell PS

    if ([String]::IsNullorEmpty($ComputerName) ) {
        Write-Verbose "Running locally."
        $Session = @{}
    }
    else {
        Write-Verbose "Running on $ComputerName."
        $Session = @{
            session = new-pssession -computername $ComputerName
        }
    }

    Invoke-Command @session -ArgumentList $SwitchName, $LocalIPAddress, $PrefixLength, $VLANID {
        param(
            [string] $SwitchName,
            [String] $LocalIPAddress,
            [Int32] $PrefixLength,
            [Int32] $VLANID
        )
        if ([string]::IsNullOrEmpty($SwitchName)) {
            $vmswitch = Get-vmswitch
            if ($null -ieq $vmswitch) {
                throw "No virtual switch found."
            }
            if ($vmswitch.count -gt 1) {
                throw "Hyper-V host contains more than one virtual switch.  Use SwitchName parameter to select a virtual switch."
            }
            $SwitchName = $vmswitch.name
        }

        Get-vmnetworkadapter -managementos -Name BGP -erroraction silentlycontinue | remove-vmnetworkadapter

        Add-vmnetworkadapter -ManagementOS -SwitchName $SwitchName -Name "BGP" | out-null
        Set-VMNetworkAdapterVlan -ManagementOS -VMNetworkAdaptername "BGP" -VlanId $VLANID -Access | out-null
        Set-NetIPInterface -InterfaceAlias "vEthernet (BGP)" -Dhcp Disabled | out-null
        Set-dnsclient -InterfaceAlias "vEthernet (BGP)" -RegisterThisConnectionsAddress $False | out-null

        new-NetIPAddress -IPAddress $LocalIPAddress -InterfaceAlias "vEthernet (BGP)" -PrefixLength $PrefixLength  | out-null

    }

    $BGPHost = [BGPHost]::New()
    $BGPhost.Computername = $ComputerName
    $BGPhost.LocalIPAddress = $LocalIPAddress
    return $BGPHost
}

function Remove-SdnExpressBGPHost {
    [CmdletBinding()]
    param(
        [string] $ComputerName = $null,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [BGPHost] $BGPHost = $null
    )

    if ($BGPHost) {
        $computername = $BGPHost.ComputerName
    }

    if ([String]::IsNullorEmpty($Computername) ) {
        Write-Verbose "Running locally."
        $Session = @{}
    }
    else {
        Write-Verbose "Running on $ComputerName."
        $Session = @{
            session = new-pssession -computername $ComputerName
        }
    }

    Invoke-Command @session {
        Get-vmnetworkadapter -managementos -Name BGP -erroraction silentlycontinue | remove-vmnetworkadapter
    }
}


function Test-SdnExpressBGP {
    [CmdletBinding()]
    param(
        [String] $RouterIPAddress,
        [String] $LocalIPAddress,
        [String] $LocalASN,
        [int32] $Wait = 3,
        [String] $ComputerName = "localhost",
        [Switch] $force,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [BGPHost] $BGPHost = $null
    )

    if ($BGPHost) {
        $ComputerName = $BGPHost.ComputerName
        $LocalIPAddress = $BGPHost.LocalIPAddress
    }

    if ([String]::IsNullorEmpty($Computername) ) {
        Write-Verbose "Running locally."
        $Session = @{}
    }
    else {
        Write-Verbose "Running on $ComputerName."
        $Session = @{
            session = new-pssession -computername $ComputerName
        }
    }

    $BGP_HEADER_LEN = 19
    $BGP_HEADER_MARKER_OFFSET = 0
    $BGP_HEADER_LENGTH_OFFSET = 16
    $BGP_HEADER_TYPE_OFFSET = 18
    $BGP_TYPES = @("", "OPEN", "UPDATE", "NOTIFICATION", "KEEPALIVE", "ROUTEREFRESH")

    $BGP_OPEN_VERSION_OFFSET = $BGP_HEADER_LEN + 0
    $BGP_OPEN_AS_OFFSET = $BGP_HEADER_LEN + 1
    $BGP_OPEN_HOLDTIME_OFFSET = $BGP_HEADER_LEN + 3
    $BGP_OPEN_BGPID_OFFSET = $BGP_HEADER_LEN + 5
    $BGP_OPEN_OPTPARMLEN_OFFSET = $BGP_HEADER_LEN + 9
    $BGP_OPEN_OPTPARM_OFFSET = $BGP_HEADER_LEN + 10
    $BGP_OPEN_OPTPARAM_TYPES = @("", "Authentication (deprecated)", "Capabilities")

    $BGP_ERROR_CODES = @("", "Message Header Error", "OPEN Message Error", "UPDATE Message Error", "Hold Timer Expired", "Finite State Machine Error", "Cease")
    $BGP_ERROR_SUBCODE_MESSAGE = @("", "Connection Not Synchronized.", "Bad Message Length.", "Bad Message Type.")
    $BGP_ERROR_SUBCODE_OPEN = @("", "Unsupported Version Number.", "Bad Peer AS.", "Bad BGP Identifier.", "Unsupported Optional Parameter.", "5 [Deprecated]", "Unacceptable Hold Time.")
    $BGP_ERROR_SUBCODE_CEASE = @("", "Maximum Number of Prefixes Reached.", "Administrative Shutdown.", "Peer De-configured.", "Administrative Reset.", "Connection Rejected.", "Other Configuration Change.", "Connection Collision Resolution.", "Out of Resources.")

    $BGP_NOTIFICATION_CODE_OFFSET = $BGP_HEADER_LEN + 0
    $BGP_NOTIFICATION_SUBCODE_OFFSET = $BGP_HEADER_LEN + 1
    $BGP_NOTIFICATION_DATA_OFFSET = $BGP_HEADER_LEN + 2

    $BGP_UPDATE_WITHDRAWN_OFFSET = $BGP_HEADER_LEN
    $BGP_PATH_ATTRIBUTE_TYPES = @("", "ORIGIN", "AS_PATH", "NEXT_HOP", "MULTI_EXIT_DISC", "LOCAL_PREF", "ATOMIC_AGGREGATE", "AGGREGATOR")
    $BGP_PATH_ATTRIBUTE_ORIGIN_VALUE = @("IGP", "EGP", "INCOMPLETE")
    $BGP_PATH_ATTRIBUTE_AS_PATH_SEGMENT_TYPE = @("", "AS_SET", "AS_SEQUENCE")

    [BGPState] $Script:bgpState = [BGPState]::Idle
    Set-BGPState Idle
    $Results = [BGPPeer]::new()
    $results.LocalIPAddress = $LocalIPAddress
    $results.LocalAS = $LocalASN
    $results.RouterIPAddress = $RouterIPAddress

    try {
        Write-Verbose "Attempting BGP connection from $localIPAddress to $RouterIPAddress"
        Invoke-Command @Session -argumentlist $LocalIPAddress,$RouterIPAddress,$wait,$force {
            param(
                $LocalIPAddress,
                $RouterIPAddress,
                $wait,
                $force
            )

            $port = "179"

            $RestoreMuxState = $false
            $mux = Get-Service -Name -erroraction silentlycontinue
            if ($null -ne $mux) {
                $muxstartup = $mux.starttype
                $muxstatus = $mux.status

                if (($muxstatus -ne "Stopped") -or ($Muxstartup -ne "Disabled")) {
                    if ($force) {
                        $RestoreMuxState = $true
                        Set-Service -Name -startup Disabled
                        stop-Service -Name
                    }
                    else {
                        throw "SLB Mux service is active.  Use -force to temporarily disable it during test."
                    }
                }
            }
            else {
                $muxstate = $null
            }

            $IPEndpoint = New-object System.Net.IPEndPoint([IPAddress]$LocalIPAddress, 0)
            try {
                $tcp = New-Object System.Net.Sockets.TcpClient($IPEndpoint)
            }
            catch {
                throw "Local IP address $LocalIPAddress not found on computer $(hostname)."
            }

            try {
                $tcp.Connect($routerIPAddress, $Port)
            }
            catch {
                throw "BGP Listener not found at RouterIPAddress $RouterIPAddress."
            }

            $tcpstream = $tcp.GetStream()
            $reader = New-Object System.IO.BinaryReader($tcpStream)
            $writer = New-Object System.IO.BinaryWriter($tcpStream)

            $reader.BaseStream.ReadTimeout = $Wait * 1000
        }

        Set-BGPState -State Connect
        $IsConnected = Invoke-Command @Session { $tcp.connected }
        if ($IsConnected) {
            Write-Verbose "BGP Connection Initiated."

            #Send OPEN
            $chars = new-BGPOpen

            Write-Verbose "Sending BGP OPEN"
            Write-Verbose "Write bytes[$($chars.count)]     $chars"

            Invoke-Command @Session -argumentlist (, $chars) {
                param(
                    [byte[]] $chars
                )
                $writer.Write([byte[]]$chars)
                $writer.Flush()
            }

            Write-Verbose "Write complete."
            Set-BGPState OpenSent

            Write-Verbose "Entering read loop."
            do {
                try {
                    $chars = Invoke-Command @Session {
                        try {
                            $chars = @()
                            $chars = @($reader.Readbyte())
                            while (($reader.PeekChar() -ne -1) -or ($tcp.Available)) {
                                $chars += $reader.Readbyte()
                            }
                            return $chars
                        }
                        catch {
                            #return @()
                            if ($_.Exception.InnerException.InnerException.NativeErrorCode -eq 10060) {
                                #timedout
                                throw "Timeout"
                            }
                            else {
                                throw $_
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "Caught. $($_)"
                    if ($_.exception.Message -eq "Timeout") {
                        #timedout NativeErrorCode 10060
                        if (!$bytesRemain) {
                            Write-Verbose "Timeout, no updates recieved within $Wait seconds. Exiting."
                            break
                        }
                    }
                    else {
                        $err = "Connection closed.  BGP active at routerIPAddress, but session rejected by remote based on localIPAddress."
                        Write-Verbose $err
                        Set-BGPState Idle
                        throw $err
                    }
                }
                $bytesRemain = $chars.count

                while ($bytesremain -gt 0) {
                    Write-Verbose "Received data, parsing header.  Buffer contains $bytesRemain bytes."
                    Write-Verbose "Buffer bytes[$($chars.count)]     $chars"

                    $header = Get-BGPHeader $chars
                    Write-Verbose ($header | ConvertTo-Json -Depth 10)
                    $bytesRemain -= $header.Length
                    Write-Verbose "$bytesRemain bytes remain to parse."

                    switch ($header.Type) {
                        "OPEN" {
                            Write-Verbose "Parsing OPEN message."
                            $open = Get-BGPOpen $chars
                            Write-Verbose ($open | ConvertTo-Json -Depth 10)

                            $Results.RouterAS = $open.AS
                            $Results.HoldTime = $open.HoldTime
                            $Results.Version = $open.Version
                            $Results.BGPID = $open.BGPID
                            foreach ($optparam in $open.optparams) {
                                $op = [BGPOptParam]::New()
                                $op.Type = $optparam.type
                                foreach ($cap in $optparam.values) {
                                    $c = [BGPCapability]::new()
                                    $c.Code = $cap.Code
                                    $c.Value = $cap.value
                                    $op.Capabilities += $c
                                }
                                $results.OptParams += $op
                            }
                            Set-BGPState OpenConfirm
                        }
                        "KEEPALIVE" {
                            if ((Get-BGPState) -in [BGPState]::OpenConfirm, [BGPState]::Established) {
                                $chars = New-BGPKeepalive

                                Write-Verbose "Sending BGP Keepalive"
                                Write-Verbose "Write bytes[$($chars.count)]     $chars"
                                Invoke-Command @Session -argumentlist (, $chars) {
                                    param(
                                        $chars
                                    )
                                    $writer.Write([byte[]]$chars)
                                    $writer.Flush()
                                }

                                Set-BGPState -State Established
                                Write-Verbose "Success, BGP session established!"
                            }
                            else {
                                Write-Verbose "Out of order Keepalive received in state $(Get-BGPState)."
                            }
                        }
                        "NOTIFICATION" {
                            Write-Verbose "Parsing NOTIFICATION message."
                            $open = Get-BGPNotification $chars
                            Write-Verbose ($open | ConvertTo-Json -Depth 10)
                            Write-Verbose "BGP peer found, but connection refused."
                            Set-BGPState -State Idle
                            throw "BGP peer found, but connection refused.  ErrorCode: $($open.Errorcode), ErrorSubcode: $($open.ErrorSubcode)"
                        }
                        "UPDATE" {
                            Write-Verbose "Parsing UPDATE message."
                            $update = Get-bgpupdate $chars
                            Write-Verbose ($update | ConvertTo-Json -Depth 10)
                            $NextHop = ($Update.PathAttributes | where-object { $_.AttrType -eq "NEXT_HOP" }).NextHop
                            $ASPath = ($Update.PathAttributes | where-object { $_.AttrType -eq "AS_PATH" }).ASPath.ASes
                            $Origin = ($Update.PathAttributes | where-object { $_.AttrType -eq "ORIGIN" }).Value
                            $LocPrf = ($Update.PathAttributes | where-object { $_.AttrType -eq "LOCAL_PREF" }).Value
                            $Metric = ($Update.PathAttributes | where-object { $_.AttrType -eq "MULTI_EXIT_DISC" }).Value

                            foreach ($prefix in $Update.Prefixes) {
                                $BGPRoute = [BGPPath]::New()
                                $BGPRoute.Prefix = $Prefix
                                $BGPRoute.NextHop = $NextHop
                                $BGPRoute.Path = $ASPath
                                $BGPRoute.LocPrf = $LocPrf
                                $BGPRoute.Metric = $Metric
                                $BGPRoute.Origin = $Origin

                                $Results.Routes += $BGPRoute
                            }
                        }
                        "ROUTEREFRESH" {
                            Write-Verbose "Parsing ROUTEREFRESH message."
                            Set-BGPState Custom
                        }
                    }

                    $chars = getBytes $chars ($header.length) $bytesremain
                    Write-Verbose "BGP State: $(Get-BGPState)"
                    Write-Verbose "Returning to read loop, waiting up to $wait seconds for more data."
                }
            } until ((Get-BGPState) -in [BGPState]::Custom, [BGPState]::Idle)
        }
        else {
            Write-Verbose "Not connected."
            throw "Listener found at BGP port 179 of $RouterIPAddress, but it closed the connection from $LocalIPAddress."
        }
    }
    finally {
        Invoke-Command @Session {
            if ($null -ne $reader) {
                $reader.Close()
            }
            if ($null -ne $writer) {
                $writer.Close()
            }
            if ($null -ne $tcp) {
                $tcp.Close()
            }
            if ($RestoreMuxState) {
                Set-Service -Name SlbMux -StartupType $MuxStartup
                if ($MuxStatus -eq "Running") {
                    Start-Service -Name SlbMux
                }
            }
        }
        if (![String]::IsNullorEmpty($Computername) ) {
            remove-pssession $session.session
        }
    }
    $results.State = (Get-BGPState)
    $results
}

Export-ModuleMember -Function Test-SdnExpressBGP
Export-ModuleMember -Function New-SdnExpressBGPHost
Export-ModuleMember -Function Remove-SdnExpressBGPHost
