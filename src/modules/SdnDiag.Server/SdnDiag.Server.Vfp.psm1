# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-VfpVMSwitchPort {
    <#
    .SYNOPSIS
        Returns a list of ports from within VFP.
    #>

    try {
        $arrayList = [System.Collections.ArrayList]::new()

        $vfpResults = vfpctrl /list-vmswitch-port
        if ($null -eq $vfpResults) {
            $msg = "Unable to retrieve vmswitch ports from vfpctrl`n{0}" -f $_
            throw New-Object System.NullReferenceException($msg)
        }

        foreach ($line in $vfpResults) {
            $line = $line.Trim()

            if ($line -like 'ITEM LIST' -or $line -ilike '===========') {
                continue
            }

            if ([string]::IsNullOrEmpty($line)) {
                continue
            }

            # lines in the VFP output that contain : contain properties and values
            # need to split these based on count of ":" to build key and values
            if ($line.Contains(":")) {
                [System.String[]]$results = $line.Split(':').Replace(" ", "").Trim()
                if ($results.Count -eq 3) {
                    $key = "$($results[0])-$($results[1])"
                    $value = $results[2]
                }
                elseif ($results.Count -eq 2) {
                    $key = $results[0]
                    $value = $results[1]
                }

                # all groups begin with this property and value so need to create a new psobject when we see these keys
                if ($key -ieq 'Portname') {
                    if ($object) {
                        [void]$arrayList.Add($object)
                    }

                    $object = New-Object -TypeName PSObject
                    $object | Add-Member -MemberType NoteProperty -Name 'PortName' -Value $value

                    continue
                }

                # add the line values to the object
                $object | Add-Member -MemberType NoteProperty -Name $key -Value $value
            }
            elseif ($line.Contains('Command list-vmswitch-port succeeded!')) {
                if ($object) {
                    [void]$arrayList.Add($object)
                }
            }
            else {
                if ($line.Contains('Port is')) {
                    $object | Add-Member -MemberType NoteProperty -Name 'PortState' -Value $line.Split(' ')[2].Replace('.', '').Trim()
                }
                elseif ($line.Contains('MAC Learning is')) {
                    $object | Add-Member -MemberType NoteProperty -Name 'MACLearning' -Value $line.Split(' ')[3].Replace('.', '').Trim()
                }
                elseif ($line.Contains('NIC is')) {
                    $object | Add-Member -MemberType NoteProperty -Name 'NICState' -Value $line.Split(' ')[2].Replace('.', '').Trim()
                }
            }
        }

        return $arrayList
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnVfpPortGroup {
    <#
    .SYNOPSIS
        Enumerates the groups contained within the specific Virtual Filtering Platform (VFP) layer specified for the port.
    .PARAMETER PortId
        The Port ID GUID for the network interface.
    .PARAMETER Layer
        Specify the target layer.
    .PARAMETER Direction
        Specify the direction
    .PARAMETER Type
        Specifies an array of IP address families. The cmdlet gets the configuration that matches the address families
    .PARAMETER Name
        Returns the specific group name. If omitted, will return all groups within the VFP layer.
    .EXAMPLE
        PS> Get-SdnVfpPortGroup -PortId '2152523D-333F-4082-ADE4-107D8CA75F5B' -Layer 'SLB_NAT_LAYER'
    .EXAMPLE
        PS> Get-SdnVfpPortGroup -PortId '2152523D-333F-4082-ADE4-107D8CA75F5B' -Layer 'SLB_NAT_LAYER' -Name 'SLB_GROUP_NAT_IPv4_IN'
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Name')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [GUID]$PortId,

        [Parameter(Mandatory = $true, ParameterSetName = 'Name')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [System.String]$Layer,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [ValidateSet('IN', 'OUT')]
        [System.String]$Direction,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [ValidateSet('IPv4', 'IPv6')]
        [System.String]$Type,

        [Parameter(Mandatory = $false, ParameterSetName = 'Name')]
        [System.String]$Name
    )

    try {
        $arrayList = [System.Collections.ArrayList]::new()
        $vfpGroups = vfpctrl /list-group /port $PortId /layer $Layer
        if ($null -eq $vfpGroups) {
            return $null
        }

        # due to how vfp handles not throwing a terminating error if port ID does not exist,
        # need to manually examine the response to see if it contains a failure
        if ($vfpGroups[0] -ilike "ERROR*") {
            "{0}" -f $vfpGroups[0] | Trace-Output -Level:Exception
            return $null
        }

        foreach ($line in $vfpGroups) {
            $line = $line.Trim()

            if ($line -like 'ITEM LIST' -or $line -ilike '===========') {
                continue
            }

            if ([string]::IsNullOrEmpty($line)) {
                continue
            }

            # in situations where the value might be nested in another line we need to do some additional data processing
            # subkey is declared below if the value is null after the split
            if ($subKey) {
                if ($null -eq $subObject) {
                    $subObject = New-Object -TypeName PSObject
                }
                if ($null -eq $subArrayList) {
                    $subArrayList = [System.Collections.ArrayList]::new()
                }

                switch ($subKey) {
                    'Conditions' {
                        # this will have a pattern of multiple lines nested under Conditions: in which we see a pattern of property:value format
                        # we also see common pattern that Match type is the next property after Conditions, so we can use that to determine when
                        # no further processing is needed for this sub value
                        if ($line.Contains('Match type')) {
                            $object | Add-Member -NotePropertyMembers @{Conditions = $subObject }

                            $subObject = $null
                            $subKey = $null
                        }

                        # if <none> is defined for conditions, we can also assume there is nothing to define and will just add
                        elseif ($line.Contains('<none>')) {
                            $object | Add-Member -MemberType NoteProperty -Name $subKey -Value 'None'

                            $subObject = $null
                            $subKey = $null
                        }

                        elseif ($line.Contains(':')) {
                            [System.String[]]$subResults = $line.Split(':').Trim()
                            $subObject | Add-Member -MemberType NoteProperty -Name $subResults[0] -Value $subResults[1]
                        }
                    }
                }
            }

            # lines in the VFP output that contain : contain properties and values
            # need to split these based on count of ":" to build key and values
            if ($line.Contains(':')) {
                [System.String[]]$results = $line.Split(':').Trim()
                if ($results.Count -eq 2) {
                    [System.String]$key = $results[0].Trim()
                    [System.String]$value = $results[1].Trim()

                    # all groups begin with this property and value so need to create a new psobject when we see these keys
                    if ($key -ieq 'Group') {
                        if ($object) {
                            [void]$arrayList.Add($object)
                        }

                        $object = New-Object -TypeName PSObject
                        $object | Add-Member -MemberType NoteProperty -Name 'Group' -Value $value

                        continue
                    }

                    if ($key -ieq 'Conditions') {
                        $subKey = $key
                        continue
                    }

                    # if the key is priority, we want to declare the value as an int value so we can properly sort the results
                    if ($key -ieq 'Priority') {
                        [int]$value = $results[1]
                    }

                    # add the line values to the object
                    $object | Add-Member -MemberType NoteProperty -Name $key -Value $value
                }
            }
            elseif ($line.Contains('Command list-group succeeded!')) {
                if ($object) {
                    [void]$arrayList.Add($object)
                }
            }
        }

        if ($Name) {
            return ($arrayList | Where-Object { $_.Group -ieq $Name })
        }

        if ($Direction) {
            $arrayList = $arrayList | Where-Object { $_.Direction -ieq $Direction }
        }

        if ($Type) {
            $arrayList = $arrayList | Where-Object { $_.Type -ieq $Type }
        }

        return ($arrayList | Sort-Object -Property Priority)
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnVfpPortLayer {
    <#
    .SYNOPSIS
        Enumerates the layers contained within Virtual Filtering Platform (VFP) for specified for the port.
    .PARAMETER PortId
        The Port ID GUID for the network interface.
    .PARAMETER Name
        Returns the specific layer name. If omitted, will return all layers within VFP.
    .EXAMPLE
        PS> Get-SdnVfpPortLayer
    .EXAMPLE
        PS> Get-SdnVfpPortLayer -PortId '2152523D-333F-4082-ADE4-107D8CA75F5B'
    #>

    param (
        [Parameter(Mandatory = $true)]
        [GUID]$PortId,

        [Parameter(Mandatory = $false)]
        [System.String]$Name
    )

    try {
        $arrayList = [System.Collections.ArrayList]::new()
        $vfpLayers = vfpctrl /list-layer /port $PortId
        if ($null -eq $vfpLayers) {
            return $null
        }

        # due to how vfp handles not throwing a terminating error if port ID does not exist,
        # need to manually examine the response to see if it contains a failure
        if ($vfpLayers[0] -ilike "ERROR*") {
            "{0}" -f $vfpLayers[0] | Trace-Output -Level:Exception
            return $null
        }

        foreach ($line in $vfpLayers) {
            $line = $line.Trim()

            if ($line -like 'ITEM LIST' -or $line -ilike '===========') {
                continue
            }

            if ([string]::IsNullOrEmpty($line)) {
                continue
            }

            # lines in the VFP output that contain : contain properties and values
            # need to split these based on count of ":" to build key and values
            if ($line.Contains(':')) {
                [System.String[]]$results = $line.Split(':').Trim()
                if ($results.Count -eq 2) {
                    [System.String]$key = $results[0].Trim()
                    [System.String]$value = $results[1].Trim()

                    # all layers begin with this property and value so need to create a new psobject when we see these keys
                    if ($key -ieq 'Layer') {
                        if ($object) {
                            [void]$arrayList.Add($object)
                        }

                        $object = New-Object -TypeName PSObject
                        $object | Add-Member -MemberType NoteProperty -Name 'Layer' -Value $value

                        continue
                    }

                    # if the key is priority, we want to declare the value as an int value so we can properly sort the results
                    if ($key -ieq 'Priority') {
                        [int]$value = $value
                    }
                    else {
                        [System.String]$value = $value
                    }
                }

                # add the line values to the object
                $object | Add-Member -MemberType NoteProperty -Name $key -Value $value
            }
            elseif ($line.Contains('Command list-layer succeeded!')) {
                if ($object) {
                    [void]$arrayList.Add($object)
                }
            }
        }

        if ($Name) {
            return ($arrayList | Where-Object { $_.Layer -eq $Name })
        }
        else {
            return ($arrayList | Sort-Object -Property Priority)
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnVfpPortRule {
    <#
    .SYNOPSIS
        Enumerates the rules contained within the specific group within Virtual Filtering Platform (VFP) layer specified for the port.
    .PARAMETER PortId
        The Port ID GUID for the network interface.
    .PARAMETER Layer
        Specify the target layer.
    .PARAMETER Group
        Specify the group layer.
    .PARAMETER Name
        Returns the specific rule name. If omitted, will return all rules within the VFP group.
    .EXAMPLE
        PS> Get-SdnVfpPortRule -PortId '2152523D-333F-4082-ADE4-107D8CA75F5B' -Layer 'SLB_NAT_LAYER' -Group 'SLB_GROUP_NAT_IPv4_IN'
    .EXAMPLE
        PS> Get-SdnVfpPortRule -PortId '2152523D-333F-4082-ADE4-107D8CA75F5B' -Layer 'SLB_NAT_LAYER' -Group 'SLB_GROUP_NAT_IPv4_IN' -Name 'SLB_DEFAULT_RULE'
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [GUID]$PortId,

        [Parameter(Mandatory = $true)]
        [System.String]$Layer,

        [Parameter(Mandatory = $true)]
        [System.String]$Group,

        [Parameter(Mandatory = $false)]
        [System.String]$Name
    )

    try {
        $arrayList = [System.Collections.ArrayList]::new()
        $vfpRules = vfpctrl /list-rule /port $PortId /layer $Layer /group $Group
        if ($null -eq $vfpRules) {
            return $null
        }

        # due to how vfp handles not throwing a terminating error if port ID does not exist,
        # need to manually examine the response to see if it contains a failure
        if ($vfpRules[0] -ilike "ERROR*") {
            "{0}" -f $vfpRules[0] | Trace-Output -Level:Exception
            return $null
        }

        foreach ($line in $vfpRules) {
            $line = $line.Trim()

            if ($line -like 'ITEM LIST' -or $line -ilike '===========') {
                continue
            }

            if ([string]::IsNullOrEmpty($line)) {
                continue
            }

            # in situations where the value might be nested in another line we need to do some additional data processing
            # subkey is declared below if the value is null after the split
            if ($subKey) {
                if ($null -eq $subObject) {
                    $subObject = New-Object -TypeName PSObject
                }
                if ($null -eq $subArrayList) {
                    $subArrayList = [System.Collections.ArrayList]::new()
                }

                switch ($subKey) {
                    'Conditions' {
                        # this will have a pattern of multiple lines nested under Conditions: in which we see a pattern of property:value format
                        # we also see common pattern that Flow TTL is the next property after Conditions, so we can use that to determine when
                        # no further processing is needed for this sub value
                        if ($line.Contains('Flow TTL')) {
                            $object | Add-Member -NotePropertyMembers @{Conditions = $subObject }

                            $subObject = $null
                            $subKey = $null
                        }

                        # if <none> is defined for conditions, we can also assume there is nothing to define and will just add
                        elseif ($line.Contains('<none>')) {
                            $object | Add-Member -MemberType NoteProperty -Name $subKey -Value 'None'

                            $subObject = $null
                            $subKey = $null
                        }

                        else {
                            [System.String[]]$subResults = $line.Split(':').Trim()
                            $subObject | Add-Member -MemberType NoteProperty -Name $subResults[0] -Value $subResults[1]
                        }
                    }
                    'Encap Destination(s)' {
                        # we typically see a format pattern of {property=value,property=value} for encap destination
                        # and should be contained all within a single line. we also see a matching pattern that FlagsEx is the next property result
                        # so we can use that to determine when no further processing is needed for this sub value
                        if ($line.Contains('FlagsEx')) {
                            $object | Add-Member -MemberType NoteProperty -Name 'Encap Destination' -Value $subObject

                            $subObject = $null
                            $subKey = $null
                        }
                        else {
                            [System.String[]]$subResults = $line.Replace('{', '').Replace('}', '').Split(',').Trim()
                            foreach ($subResult in $subResults) {
                                [System.String]$subKeyName = $subResult.Split('=')[0].Trim()
                                [System.String]$subKeyValue = $subResult.Split('=')[1].Trim()

                                $subObject | Add-Member -MemberType NoteProperty -Name $subKeyName -Value $subKeyValue
                            }
                        }
                    }
                }

                # since we are processing sub values, we want to move to the next line and not do any further processing
                continue
            }

            # lines in the VFP output that contain : contain properties and values
            # need to split these based on count of ":" to build key and values
            if ($line.Contains(':')) {
                [System.String[]]$results = $line.Split(':')
                if ($results.Count -eq 2) {
                    [System.String]$key = $results[0].Trim()
                    [System.String]$value = $results[1].Trim()

                    # all groups begin with this property and value so need to create a new psobject when we see these keys
                    if ($key -ieq 'RULE') {
                        if ($object) {
                            [void]$arrayList.Add($object)
                        }

                        $object = New-Object -TypeName PSObject
                        $object | Add-Member -MemberType NoteProperty -Name 'Rule' -Value $value

                        continue
                    }

                    # because some rules defined within groups do not have a rule name defined such as NAT layers,
                    # grab the friendly name and update the ps object
                    if ($key -ieq 'Friendly name') {
                        if ([String]::IsNullOrEmpty($object.Rule)) {
                            $object.Rule = $value
                        }
                    }

                    if ($key -ieq 'Conditions' -or $key -ieq 'Encap Destination(s)') {
                        $subKey = $key
                        continue
                    }

                    # if the key is priority, we want to declare the value as an int value so we can properly sort the results
                    if ($key -ieq 'Priority') {
                        [int]$value = $value
                    }

                    # add the line values to the object
                    $object | Add-Member -MemberType NoteProperty -Name $key -Value $value
                }
            }
            elseif ($line.Contains('Command list-rule succeeded!')) {
                if ($object) {
                    [void]$arrayList.Add($object)
                }
            }
        }

        if ($Name) {
            return ($arrayList | Where-Object { $_.Rule -ieq $Name -or $_.'Friendly name' -ieq $Name })
        }

        return ($arrayList | Sort-Object -Property Priority)
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnVfpPortState {
    <#
    .SYNOPSIS
        Returns the current VFP port state for a particular port Id.
    .DESCRIPTION
        Executes 'vfpctrl.exe /get-port-state /port $PortId' to return back the current state of the port specified.
    .PARAMETER PortId
        The Port ID GUID for the network interface.
    .EXAMPLE
        PS> Get-SdnVfpPortState -PortId 3DC59D2B-9BFE-4996-AEB6-2589BD20B559
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [GUID]$PortId
    )

    try {
        $object = New-Object -TypeName PSObject

        $vfpPortState = vfpctrl.exe /get-port-state /port $PortId
        if ($null -eq $vfpPortState) {
            $msg = "Unable to locate port ID {0} from vfpctrl`n{1}" -f $PortId, $_
            throw New-Object System.NullReferenceException($msg)
        }

        foreach ($line in $vfpPortState) {
            $trimmedLine = $line.Replace(':', '').Trim()

            # look for true/false and then seperate out the key/value pairs
            # we will convert the true/false values to boolean when adding to the object
            if ($trimmedLine -match '(.*)\s+(True|False)') {
                $object | Add-Member -MemberType NoteProperty -Name $Matches.1 -Value ([System.Convert]::ToBoolean($Matches.2))
                continue
            }

            # look for enabled/disabled and then seperate out the key/value pairs
            if ($trimmedLine -match '(.*)\s+(Enabled|Disabled)') {
                $object | Add-Member -MemberType NoteProperty -Name $Matches.1 -Value $Matches.2
                continue
            }
        }

        return $object
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnVfpVmSwitchPort {
    <#
    .SYNOPSIS
        Returns a list of ports from within virtual filtering platform.
    .PARAMETER PortName
        The port name of the VFP interface
    .PARAMETER VMName
        The Name of the Virtual Machine
    .PARAMETER VMID
        The ID of the Virtual Machine
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnVfpVmSwitchPort -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Get-SdnVfpVmSwitchPort -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnVfpVmSwitchPort -VMName 'SDN-MUX01'
    .EXAMPLE
        PS> Get-SdnVfpVmSwitchPort -VMID 699FBDA2-15A0-4D73-A6EF-9D55623A27CE
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'Port')]
        [System.String]$PortName,

        [Parameter(Mandatory = $false, Position = 2, ParameterSetName = 'VMID')]
        [System.String]$VMID,

        [Parameter(Mandatory = $false, Position = 3, ParameterSetName = 'VMName')]
        [System.String]$VMName,

        [Parameter(Mandatory = $false, Position = 4, ParameterSetName = 'Port')]
        [Parameter(Mandatory = $false, Position = 4, ParameterSetName = 'VMID')]
        [Parameter(Mandatory = $false, Position = 4, ParameterSetName = 'VMName')]
        [Parameter(Mandatory = $false, Position = 4, ParameterSetName = 'Default')]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false, Position = 5, ParameterSetName = 'Port')]
        [Parameter(Mandatory = $false, Position = 4, ParameterSetName = 'VMID')]
        [Parameter(Mandatory = $false, Position = 4, ParameterSetName = 'VMName')]
        [Parameter(Mandatory = $false, Position = 4, ParameterSetName = 'Default')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            $results = Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -ScriptBlock { Get-SdnVfpVmSwitchPort }
        }
        else {
            $results = Get-VfpVMSwitchPort
        }

        switch ($PSCmdlet.ParameterSetName) {
            'Port' { return ($results | Where-Object { $_.PortName -ieq $PortName }) }
            'VMID' { return ($results | Where-Object { $_.VMID -ieq $VMID }) }
            'VMName' { return ($results | Where-Object { $_.VMName -ieq $VMName }) }
            default { return $results }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Show-SdnVfpPortConfig {
    <#
    .SYNOPSIS
        Enumerates the VFP layers, groups and rules contained within Virtual Filtering Platform (VFP) for the specified port.
    .PARAMETER PortId
        The Port ID GUID for the network interface.
    .PARAMETER Direction
        Specify the direction
    .PARAMETER Type
        Specifies an array of IP address families. The cmdlet gets the configuration that matches the address families
    .EXAMPLE
        PS Show-SdnVfpPortConfig -PortId 8440FB77-196C-402E-8564-B0EF9E5B1931
    .EXAMPLE
        PS> Show-SdnVfpPortConfig -PortId 8440FB77-196C-402E-8564-B0EF9E5B1931 -Direction IN
    .EXAMPLE
        PS> Show-SdnVfpPortConfig -PortId 8440FB77-196C-402E-8564-B0EF9E5B1931 -Direction IN -Type IPv4
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [GUID]$PortId,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [ValidateSet('IPv4', 'IPv6')]
        [System.String]$Type,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [ValidateSet('IN', 'OUT')]
        [System.String]$Direction
    )

    try {
        $vfpLayers = Get-SdnVfpPortLayer -PortId $PortId
        if ($null -eq $vfpLayers) {
            "Unable to locate PortId {0}" -f $PortId | Trace-Output -Level:Exception
            return $null
        }

        foreach ($layer in $vfpLayers) {
            "== Layer: {0} ==" -f $layer.LAYER | Write-Host -ForegroundColor:Magenta

            if ($Direction) {
                $vfpGroups = Get-SdnVfpPortGroup -PortId $PortId -Layer $layer.LAYER -Direction $Direction
            }
            else {
                $vfpGroups = Get-SdnVfpPortGroup -PortId $PortId -Layer $layer.LAYER
            }

            if ($Type) {
                $vfpGroups = $vfpGroups | Where-Object { $_.Type -ieq $Type }
            }

            foreach ($group in $vfpGroups) {
                "== Group: {0} ==" -f $group.GROUP | Write-Host -ForegroundColor:Yellow
                Get-SdnVfpPortRule -PortId $PortId -Layer $layer.LAYER -Group $group.GROUP | Format-Table -AutoSize
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
