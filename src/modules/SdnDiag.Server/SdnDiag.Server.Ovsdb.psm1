# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

enum OvsdbTable {
    ms_vtep
    ms_firewall
    ServiceInsertion
}

function Get-OvsdbAddressMapping {
    <#
    .SYNOPSIS
        Returns a list of address mappings from within the OVSDB database.
    .EXAMPLE
        PS> Get-OvsdbAddressMapping
    #>

    try {
        $arrayList = [System.Collections.ArrayList]::new()

        $ovsdbResults = Get-OvsdbDatabase -Table ms_vtep
        $paMappingTable = $ovsdbResults | Where-Object { $_.caption -eq 'Physical_Locator table' }
        $caMappingTable = $ovsdbResults | Where-Object { $_.caption -eq 'Ucast_Macs_Remote table' }
        $logicalSwitchTable = $ovsdbResults | Where-Object { $_.caption -eq 'Logical_Switch table' }

        if ($null -eq $caMappingTable) {
            return $null
        }

        # enumerate the json rules for each of the tables and create psobject for the mappings
        # unfortunately these values do not return in key/value pair and need to manually map each property
        foreach ($caMapping in $caMappingTable.Data) {
            $mac = $caMapping[0]
            $uuid = $caMapping[1][1]
            $ca = $caMapping[2]
            $locator = $caMapping[3][1]
            $logicalSwitch = $caMapping[4][1]
            $mappingType = $caMapping[5]

            $pa = [string]::Empty
            $encapType = [string]::Empty
            $rdid = [string]::Empty
            $vsid = 0

            # Get PA from locator table
            foreach ($paMapping in $paMappingTable.Data) {
                $curLocator = $paMapping[0][1]
                if ($curLocator -eq $locator) {
                    $pa = $paMapping[3]
                    $encapType = $paMapping[4]
                    break
                }
            }

            # Get Rdid and VSID from logical switch table
            foreach ($switch in $logicalSwitchTable.Data) {
                $curSwitch = $switch[0][1]
                if ($curSwitch -eq $logicalSwitch) {
                    $rdid = $switch[1]
                    $vsid = $switch[3]
                    break
                }
            }

            # create the psobject now that we have all the mappings identified
            $result = New-Object PSObject -Property @{
                UUID            = $uuid
                CustomerAddress = $ca
                ProviderAddress = $pa
                MAC             = $mac
                RoutingDomainID = $rdid
                VirtualSwitchID = $vsid
                MappingType     = $mappingType
                EncapType       = $encapType
            }

            # add the psobject to the array
            [void]$arrayList.Add($result)
        }

        return $arrayList
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}


function Get-OvsdbDatabase {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [OvsdbTable]$Table
    )

    try {
        $localPort = Get-NetTCPConnection -LocalPort:6641 -ErrorAction:SilentlyContinue
        if ($null -eq $localPort){
            throw New-Object System.NullReferenceException("No endpoint listening on port 6641. Ensure NCHostAgent service is running.")
        }

        $cmdline = "ovsdb-client.exe dump tcp:127.0.0.1:6641 -f json {0}" -f $Table
        $databaseResults = Invoke-Expression $cmdline | ConvertFrom-Json

        if($null -eq $databaseResults){
            $msg = "Unable to retrieve OVSDB results`n`t{0}" -f $_
            throw New-Object System.NullReferenceException($msg)
        }
        else {
            return $databaseResults
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-OvsdbFirewallRuleTable {
    <#
    .SYNOPSIS
        Returns a list of firewall rules defined within the firewall table of the OVSDB database.
    .EXAMPLE
        PS> Get-OvsdbFirewallRuleTable
    #>

    try {
        $arrayList = [System.Collections.ArrayList]::new()

        $ovsdbResults = Get-OvsdbDatabase -Table ms_firewall
        $firewallTable = $ovsdbResults | Where-Object { $_.caption -eq 'FW_Rules table' }

        if ($null -eq $firewallTable) {
            return $null
        }
        # enumerate the json rules and create object for each firewall rule returned
        # there is no nice way to generate this and requires manually mapping as only the values are return
        foreach ($obj in $firewallTable.data) {
            $result = New-Object PSObject -Property @{
                uuid             = $obj[0][1]
                action           = $obj[1]
                direction        = $obj[2]
                dst_ip_addresses = $obj[3]
                dst_ports        = $obj[4]
                logging_state    = $obj[5]
                priority         = $obj[6]
                protocols        = $obj[7]
                rule_id          = $obj[8]
                rule_state       = $obj[9]
                rule_type        = $obj[10]
                src_ip_addresses = $obj[11]
                src_ports        = $obj[12]
                vnic_id          = $obj[13].Trim('{', '}')
            }

            # add the psobject to array list
            [void]$arrayList.Add($result)
        }

        return $arrayList
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-OvsdbGlobalTable {
    <#
    .SYNOPSIS
        Returns the global table configuration from OVSDB database.
    .EXAMPLE
        PS> Get-OvsdbGlobalTable
    #>

    try {
        $arrayList = [System.Collections.ArrayList]::new()

        $ovsdbResults = Get-OvsdbDatabase -Table ms_vtep
        $globalTable = $ovsdbResults | Where-Object { $_.caption -eq 'Global table' }

        if ($null -eq $globalTable) {
            return $null
        }

        # enumerate the json results and add to psobject
        foreach ($obj in $globalTable.data) {
            $result = New-Object PSObject -Property @{
                uuid     = $obj[0][1]
                cur_cfg  = $obj[1]
                next_cfg = $obj[4]
                switches = $obj[6][1]
            }
            # add the psobject to array
            [void]$arrayList.Add($result)
        }

        return $arrayList
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-OvsdbPhysicalPortTable {
    <#
    .SYNOPSIS
        Returns a list of ports defined within the Physical_Port table of the OVSDB database.
    .EXAMPLE
        PS> Get-OvsdbPhysicalPortTable
    #>

    try {
        $arrayList = [System.Collections.ArrayList]::new()

        $ovsdbResults = Get-OvsdbDatabase -Table ms_vtep
        $portTable = $ovsdbResults | Where-Object { $_.caption -eq 'Physical_Port table' }

        if ($null -eq $portTable) {
            return $null
        }

        # enumerate the json objects and create psobject for each port
        foreach ($obj in $portTable.data) {
            $result = New-Object PSObject -Property @{
                uuid        = $obj[0][1]
                description = $obj[1]
                name        = $obj[2].Trim('{', '}')
            }
            # there are numerous key/value pairs within this object with some having different properties
            # enumerate through the properties and add property and value for each on that exist
            foreach ($property in $obj[4][1]) {
                $result | Add-Member -MemberType NoteProperty -Name $property[0] -Value $property[1]
            }

            # add the psobject to array
            [void]$arrayList.Add($result)
        }

        return $arrayList
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-OvsdbUcastMacRemoteTable {
    <#
    .SYNOPSIS
        Returns a list of mac addresses defined within the Ucast_Macs_Remote table of the OVSDB database.
    .EXAMPLE
        PS> Get-OvsdbUcastMacRemoteTable
    #>

    try {
        $arrayList = [System.Collections.ArrayList]::new()

        $ovsdbResults = Get-OvsdbDatabase -Table ms_vtep
        $ucastMacsRemoteTable = $ovsdbResults | Where-Object { $_.caption -eq 'Ucast_Macs_Remote table' }

        if ($null -eq $ucastMacsRemoteTable) {
            return $null
        }

        # enumerate the json objects and create psobject for each port
        foreach ($obj in $ucastMacsRemoteTable.data) {
            $result = New-Object PSObject -Property @{
                uuid           = $obj[1][1]
                mac            = $obj[0]
                ipaddr         = $obj[2]
                locator        = $obj[3][1]
                logical_switch = $obj[4][1]
                mapping_type   = $obj[5]
            }

            [void]$arrayList.Add($result)
        }

        return $arrayList
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnOvsdbAddressMapping {
    <#
    .SYNOPSIS
        Gets the address mappings from OVSDB.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER AsJob
        Switch indicating to trigger a background job to perform the operation.
    .PARAMETER PassThru
        Switch indicating to wait for background job completes and display results to current session.
    .PARAMETER Timeout
        Specify the timeout duration to wait before job is automatically terminated. If omitted, defaults to 300 seconds.
    .EXAMPLE
        PS> Get-SdnOvsdbAddressMapping
    .EXAMPLE
        PS> Get-SdnOvsdbAddressMapping -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Get-SdnOvsdbAddressMapping -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnOvsdbAddressMapping -ComputerName 'Server01','Server02' -AsJob
    .EXAMPLE
        PS> Get-SdnOvsdbAddressMapping -ComputerName 'Server01','Server02' -AsJob -PassThru
    .EXAMPLE
        PS> Get-SdnOvsdbAddressMapping -ComputerName 'Server01','Server02' -AsJob -PassThru -Timeout 600
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$AsJob,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$PassThru,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [int]$Timeout = 300
    )

    try {
        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock { Get-SdnOvsdbAddressMapping } -Credential $Credential `
                -AsJob:($AsJob.IsPresent) -PassThru:($PassThru.IsPresent) -ExecutionTimeout $Timeout
        }
        else {
            Get-OvsdbAddressMapping
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnOvsdbFirewallRuleTable {
    <#
    .SYNOPSIS
        Gets the firewall rules from OVSDB
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER AsJob
        Switch indicating to trigger a background job to perform the operation.
    .PARAMETER PassThru
        Switch indicating to wait for background job completes and display results to current session.
    .PARAMETER Timeout
        Specify the timeout duration to wait before job is automatically terminated. If omitted, defaults to 300 seconds.
    .EXAMPLE
        PS> Get-SdnOvsdbFirewallRuleTable -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Get-SdnOvsdbFirewallRuleTable -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnOvsdbFirewallRuleTable -ComputerName 'Server01','Server02' -AsJob
    .EXAMPLE
        PS> Get-SdnOvsdbFirewallRuleTable -ComputerName 'Server01','Server02' -AsJob -PassThru
    .EXAMPLE
        PS> Get-SdnOvsdbFirewallRuleTable -ComputerName 'Server01','Server02' -AsJob -PassThru -Timeout 600
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$AsJob,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$PassThru,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [int]$Timeout = 300
    )

    try {
        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock { Get-SdnOvsdbFirewallRuleTable } -Credential $Credential `
                -AsJob:($AsJob.IsPresent) -PassThru:($PassThru.IsPresent) -ExecutionTimeout $Timeout
        }
        else {
            Get-OvsdbFirewallRuleTable
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnOvsdbGlobalTable {
    <#
    .SYNOPSIS
        Gets the global table results from OVSDB.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER AsJob
        Switch indicating to trigger a background job to perform the operation.
    .PARAMETER PassThru
        Switch indicating to wait for background job completes and display results to current session.
    .PARAMETER Timeout
        Specify the timeout duration to wait before job is automatically terminated. If omitted, defaults to 300 seconds.
    .EXAMPLE
        PS> Get-SdnOvsdbGlobalTable -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Get-SdnOvsdbGlobalTable -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnOvsdbGlobalTable -ComputerName 'Server01','Server02' -AsJob
    .EXAMPLE
        PS> Get-SdnOvsdbGlobalTable -ComputerName 'Server01','Server02' -AsJob -PassThru
    .EXAMPLE
        PS> Get-SdnOvsdbGlobalTable -ComputerName 'Server01','Server02' -AsJob -PassThru -Timeout 600
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$AsJob,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$PassThru,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [int]$Timeout = 300
    )

    try {
        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock { Get-SdnOvsdbGlobalTable } -Credential $Credential `
                -AsJob:($AsJob.IsPresent) -PassThru:($PassThru.IsPresent) -ExecutionTimeout $Timeout
        }
        else {
            Get-OvsdbGlobalTable
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnOvsdbPhysicalPortTable {
    <#
    .SYNOPSIS
        Gets the physical port table results from OVSDB.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER AsJob
        Switch indicating to trigger a background job to perform the operation.
    .PARAMETER PassThru
        Switch indicating to wait for background job completes and display results to current session.
    .PARAMETER Timeout
        Specify the timeout duration to wait before job is automatically terminated. If omitted, defaults to 300 seconds.
    .EXAMPLE
        PS> Get-SdnOvsdbPhysicalPortTable -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Get-SdnOvsdbPhysicalPortTable -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnOvsdbPhysicalPortTable -ComputerName 'Server01','Server02' -AsJob
    .EXAMPLE
        PS> Get-SdnOvsdbPhysicalPortTable -ComputerName 'Server01','Server02' -AsJob -PassThru
    .EXAMPLE
        PS> Get-SdnOvsdbPhysicalPortTable -ComputerName 'Server01','Server02' -AsJob -PassThru -Timeout 600
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$AsJob,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$PassThru,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [int]$Timeout = 300
    )

    try {
        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock { Get-SdnOvsdbPhysicalPortTable } -Credential $Credential `
                -AsJob:($AsJob.IsPresent) -PassThru:($PassThru.IsPresent) -ExecutionTimeout $Timeout
        }
        else {
            Get-OvsdbPhysicalPortTable
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnOvsdbUcastMacRemoteTable {
    <#
    .SYNOPSIS
        Gets the ucast mac remote table results from OVSDB.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER AsJob
        Switch indicating to trigger a background job to perform the operation.
    .PARAMETER PassThru
        Switch indicating to wait for background job completes and display results to current session.
    .PARAMETER Timeout
        Specify the timeout duration to wait before job is automatically terminated. If omitted, defaults to 300 seconds.
    .EXAMPLE
        PS> Get-SdnOvsdbUcastMacRemoteTable -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Get-SdnOvsdbUcastMacRemoteTable -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnOvsdbUcastMacRemoteTable -ComputerName 'Server01','Server02' -AsJob
    .EXAMPLE
        PS> Get-SdnOvsdbUcastMacRemoteTable -ComputerName 'Server01','Server02' -AsJob -PassThru
    .EXAMPLE
        PS> Get-SdnOvsdbUcastMacRemoteTable -ComputerName 'Server01','Server02' -AsJob -PassThru -Timeout 600
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$AsJob,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$PassThru,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [int]$Timeout = 300
    )

    try {
        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock { Get-SdnOvsdbUcastMacRemoteTable } -Credential $Credential `
                -AsJob:($AsJob.IsPresent) -PassThru:($PassThru.IsPresent) -ExecutionTimeout $Timeout
        }
        else {
            Get-OvsdbUcastMacRemoteTable
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
