# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Set-VMNetworkAdapterPortProfile {
    <#
    .SYNOPSIS
        Configures the port profile applied to the virtual machine network interfaces.
    .PARAMETER VMName
        Specifies the name of the virtual machine.
    .PARAMETER MacAddress
        Specifies the MAC address of the VM network adapter.
    .PARAMETER ProfileId
        The InstanceID of the Network Interface taken from Network Controller.
    .PARAMETER ProfileData
        1 = VfpEnabled, 2 = VfpDisabled (usually in the case of Mux). If ommited, defaults to 1.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$VMName,

        [Parameter(Mandatory = $true)]
        [System.String]$MacAddress,

        [Parameter(Mandatory = $true)]
        [System.Guid]$ProfileId,

        [Parameter(Mandatory = $false)]
        [System.Int16]$ProfileData = 1
    )

    [System.Guid]$portProfileFeatureId = "9940cd46-8b06-43bb-b9d5-93d50381fd56"
    [System.Guid]$vendorId  = "1FA41B39-B444-4E43-B35A-E1F7985FD548"

    try {
        if ($null -eq (Get-Module -Name Hyper-V)) {
            Import-Module -Name Hyper-V -Force
        }

        $vmNic = Get-VMNetworkAdapter -VMName $VmName | Where-Object {$_.MacAddress -ieq $MacAddress}
        if ($null -eq $vmNic) {
            "Unable to locate VMNetworkAdapter" | Trace-Output -Level:Exception
            return
        }

        $portProfileDefaultSetting = Get-VMSystemSwitchExtensionPortFeature -FeatureId $portProfileFeatureId -ErrorAction Stop
        $portProfileDefaultSetting.SettingData.ProfileId = $ProfileId.ToString("B")
        $portProfileDefaultSetting.SettingData.NetCfgInstanceId = "{56785678-a0e5-4a26-bc9b-c0cba27311a3}"
        $portProfileDefaultSetting.SettingData.CdnLabelString = "TestCdn"
        $portProfileDefaultSetting.SettingData.CdnLabelId = 1111
        $portProfileDefaultSetting.SettingData.ProfileName = "Testprofile"
        $portProfileDefaultSetting.SettingData.VendorId = $vendorId.ToString("B")
        $portProfileDefaultSetting.SettingData.VendorName = "NetworkController"
        $portProfileDefaultSetting.SettingData.ProfileData = $ProfileData

        $currentProfile = Get-VMSwitchExtensionPortFeature -FeatureId $portProfileFeatureId -VMNetworkAdapter $vmNic
        if ($null -eq $currentProfile) {
            "Port profile not previously configured" | Trace-Output
            Add-VMSwitchExtensionPortFeature -VMSwitchExtensionFeature  $portProfileDefaultSetting -VMNetworkAdapter $vmNic
        }
        else {
            "Current Settings: ProfileId [{0}] ProfileData [{1}]" -f $currentProfile.SettingData.ProfileId, $currentProfile.SettingData.ProfileData | Trace-Output

            $currentProfile.SettingData.ProfileId = $ProfileId.ToString("B")
            $currentProfile.SettingData.ProfileData = $ProfileData
            $currentProfile.SettingData.VendorId = $vendorId.ToString("B")

            Set-VMSwitchExtensionPortFeature -VMSwitchExtensionFeature $currentProfile -VMNetworkAdapter $vmNic
        }

        "Successfully created/added Port Profile for VM [{0})], Adapter [{1}], PortProfileId [{2}], ProfileData [{3}]" -f $vmNic.VMName, $vmNic.Name, $ProfileId.ToString(), $ProfileData | Trace-Output
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnNetAdapterEncapOverheadConfig {
    <#
    .SYNOPSIS
        Retrieves the EncapOverhead and JumboPacket properties of each network interface attached to vmswitch
    .EXAMPLE
        PS> Get-SdnNetAdapterEncapOverheadConfig
    #>

    try {
        $switchArrayList = [System.Collections.ArrayList]::new()

        foreach ($switch in (Get-VMSwitch)) {
            $interfaceArrayList = [System.Collections.ArrayList]::new()
            $supportsEncapOverhead = $false
            $encapOverheadValue = $null
            $supportsJumboPacket = $false
            $jumboPacketValue = $null

            # enumerate each of the physical network adapters that are bound to the vmswitch
            foreach ($physicalNicIfDesc in $switch.NetAdapterInterfaceDescriptions) {

                # get the encap overhead settings for each of the network interfaces within the vm switch team
                $encapOverhead = Get-NetAdapterAdvancedProperty -InterfaceDescription $physicalNicIfDesc -RegistryKeyword "*Encapoverhead" -ErrorAction SilentlyContinue
                if ($null -eq $encapoverhead) {
                    "Network interface {0} does not support EncapOverhead." -f $physicalNicIfDesc | Trace-Output -Level:Warning
                }
                else {
                    $supportsEncapOverhead = $true
                    [int]$encapOverheadValue = $encapoverhead.DisplayValue
                }

                # get the jumbo packet settings for each of the network interfaces within the vm switch team
                $jumboPacket = Get-NetAdapterAdvancedProperty -InterfaceDescription $physicalNicIfDesc -RegistryKeyword "*JumboPacket" -ErrorAction SilentlyContinue
                if ($null -eq $jumboPacket) {
                    "Network interface {0} does not support JumboPacket." -f $physicalNicIfDesc | Trace-Output -Level:Warning
                }
                else {
                    $supportsJumboPacket = $true
                    [int]$jumboPacketValue = $jumboPacket.RegistryValue[0]
                }

                $object = [PSCustomObject]@{
                    Switch               = $switch.Name
                    NetworkInterface     = $physicalNicIfDesc
                    EncapOverheadEnabled = $supportsEncapOverhead
                    EncapOverheadValue   = $encapOverheadValue
                    JumboPacketEnabled   = $supportsJumboPacket
                    JumboPacketValue     = $jumboPacketValue
                }

                # add each network interface to the interface arraylist
                [void]$interfaceArrayList.Add($object)
            }

            # add each of the switches to the switch hash table
            [void]$switchArrayList.Add($interfaceArrayList)
        }

        return $switchArrayList
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

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

function Get-SdnProviderAddress {
    <#
    .SYNOPSIS
        Retrieves the Provider Address that is assigned to the computer.
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
        PS> Get-SdnProviderAddress -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Get-SdnProviderAddress -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnProviderAddress -ComputerName 'Server01','Server02' -AsJob
    .EXAMPLE
        PS> Get-SdnProviderAddress -ComputerName 'Server01','Server02' -AsJob -PassThru
    .EXAMPLE
        PS> Get-SdnProviderAddress -ComputerName 'Server01','Server02' -AsJob -PassThru -Timeout 600
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
            Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock { Get-SdnProviderAddress } -Credential $Credential `
                -AsJob:($AsJob.IsPresent) -PassThru:($PassThru.IsPresent) -ExecutionTimeout $Timeout
        }
        else {
            Get-ProviderAddress
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnServerConfigurationState {
    <#
    .SYNOPSIS
        Outputs a set of configuration state files for the server role.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .EXAMPLE
        PS> Get-SdnServerConfigurationState -OutputDirectory "C:\Temp\CSS_SDN"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    $ProgressPreference = 'SilentlyContinue'

    try {
        $config = Get-SdnRoleConfiguration -Role:Server
        [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath "ConfigState"
        [System.IO.FileInfo]$regDir = Join-Path -Path $OutputDirectory.FullName -ChildPath "Registry"

        "Collect configuration state details for role {0}" -f $config.Name | Trace-Output

        if (-NOT (Initialize-DataCollection -Role:Server -FilePath $OutputDirectory.FullName -MinimumMB 100)) {
            throw New-Object System.Exception("Unable to initialize environment for data collection")
        }

        # dump out the regkey properties
        Export-RegistryKeyConfigDetails -Path $config.properties.regKeyPaths -OutputDirectory $regDir.FullName

        # Gather VFP port configuration details
        "Gathering VFP port details" | Trace-Output -Level:Verbose
        foreach ($vm in (Get-WmiObject -na root\virtualization\v2 msvm_computersystem)) {
            foreach ($vma in $vm.GetRelated("Msvm_SyntheticEthernetPort")) {
                foreach ($port in $vma.GetRelated("Msvm_SyntheticEthernetPortSettingData").GetRelated("Msvm_EthernetPortAllocationSettingData").GetRelated("Msvm_EthernetSwitchPort")) {

                    $outputDir = New-Item -Path (Join-Path -Path $OutputDirectory.FullName -ChildPath "VFP\$($vm.ElementName)") -ItemType Directory -Force
                    vfpctrl /list-nat-range /port $($port.Name) | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix 'NatInfo' -Name $port.Name -FileType txt
                    vfpctrl /list-rule /port $($port.Name) | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix 'RuleInfo' -Name $port.Name -FileType txt
                    vfpctrl /list-mapping /port $($port.Name) | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix 'ListMapping' -Name $port.Name -FileType txt
                    vfpctrl /get-port-flow-settings /port $($port.Name) | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix 'PortFlowSettings' -Name $port.Name -FileType txt
                    vfpctrl /get-port-flow-stats /port $($port.Name) | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix 'PortFlowStats' -Name $port.Name -FileType txt
                    vfpctrl /get-flow-stats /port $($port.Name) | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix 'FlowStats' -Name $port.Name -FileType txt
                    vfpctrl /get-port-state /port $($port.Name) | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix 'PortState' -Name $port.Name -FileType txt

                    Get-SdnVfpPortState -PortId $($port.Name) | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix 'PortState' -Name $port.Name -FileType json
                }
            }
        }

        vfpctrl /list-vmswitch-port | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'vfpctrl_list-vmswitch-port' -FileType txt
        Get-SdnVfpVmSwitchPort | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnVfpVmSwitchPort' -FileType csv
        Get-SdnVfpVmSwitchPort | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnVfpVmSwitchPort' -FileType json

        # Gather OVSDB databases
        "Gathering ovsdb database output" | Trace-Output -Level:Verbose
        ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_vtep | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'ovsdb_vtep' -FileType txt
        ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_firewall | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'ovsdb_firewall' -FileType txt
        ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_service_insertion | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'ovsdb_serviceinsertion' -FileType txt

        Get-SdnOvsdbAddressMapping | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnOvsdbAddressMapping' -FileType csv
        Get-SdnOvsdbFirewallRuleTable | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnOvsdbFirewallRuleTable' -FileType csv
        Get-SdnOvsdbGlobalTable | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnOvsdbGlobalTable' -FileType csv
        Get-SdnOvsdbPhysicalPortTable | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnOvsdbPhysicalPortTable' -FileType csv
        Get-SdnOvsdbUcastMacRemoteTable | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnOvsdbUcastMacRemoteTable' -FileType csv

        # Gather Hyper-V network details
        "Gathering hyper-v configuration details" | Trace-Output -Level:Verbose
        Get-PACAMapping | Sort-Object PSComputerName | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-PACAMapping' -FileType txt -Format Table
        Get-ProviderAddress | Sort-Object PSComputerName | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-ProviderAddress' -FileType txt -Format Table
        Get-CustomerRoute | Sort-Object PSComputerName | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-CustomerRoute' -FileType txt -Format Table
        Get-NetAdapterVPort | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetAdapterVPort' -FileType txt -Format Table
        Get-NetAdapterVmqQueue | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetAdapterVmqQueue' -FileType txt -Format Table
        Get-SdnNetAdapterEncapOverheadConfig | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnNetAdapterEncapOverheadConfig' -FileType txt -Format Table
        Get-VMSwitch | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMSwitch' -FileType txt -Format List
        Get-VMSwitchTeam | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMSwitchTeam' -FileType txt -Format List
        Get-SdnVMNetworkAdapterPortProfile -AllVMs | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnVMNetworkAdapterPortProfile' -FileType txt -Format Table
        Get-VMNetworkAdapterIsolation | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMNetworkAdapterIsolation' -FileType txt -Format Table
        Get-VMNetworkAdapterRoutingDomainMapping | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMNetworkAdapterRoutingDomainMapping' -FileType txt -Format Table
        Get-VMSystemSwitchExtensionPortFeature -FeatureId "9940cd46-8b06-43bb-b9d5-93d50381fd56" | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMSystemSwitchExtensionPortFeature' -FileType json

        Get-GeneralConfigurationState -OutputDirectory $OutputDirectory.FullName
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }

    $ProgressPreference = 'Continue'
}

function Get-SdnVMNetworkAdapter {
    <#
    .SYNOPSIS
        Retrieves the virtual machine network adapters that are allocated on a hyper-v host
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers. To specify the local computer, type the computer name, localhost, or a dot (.). When the computer is in a different domain than the user, the fully qualified domain name is required
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER AsJob
        Switch indicating to trigger a background job to perform the operation.
    .PARAMETER PassThru
        Switch indicating to wait for background job completes and display results to current session.
    .PARAMETER Timeout
        Specify the timeout duration to wait before job is automatically terminated. If omitted, defaults to 600 seconds.
    .EXAMPLE
        PS> Get-SdnVMNetworkAdapter -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Get-SdnVMNetworkAdapter -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnVMNetworkAdapter -ComputerName 'Server01','Server02' -AsJob
    .EXAMPLE
        PS> Get-SdnVMNetworkAdapter -ComputerName 'Server01','Server02' -AsJob -PassThru
    .EXAMPLE
        PS> Get-SdnVMNetworkAdapter -ComputerName 'Server01','Server02' -AsJob -PassThru -Timeout 600
    #>

    param (
        [Parameter(Mandatory = $true)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [VMState]$VmState = 'Running',

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$AsJob,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$PassThru,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [int]$Timeout = 600
    )

    try {
        $scriptBlock = {
            $virtualMachines = Get-VM | Where-Object { $_.State -eq [String]$using:VmState }
            $virtualMachines | Get-VMNetworkAdapter
        }

        Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential `
            -AsJob:($AsJob.IsPresent) -PassThru:($PassThru.IsPresent) -ExecutionTimeout $Timeout
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnVMNetworkAdapterPortProfile {
    <#
    .SYNOPSIS
        Retrieves the port profile applied to the virtual machine network interfaces.
    .PARAMETER VMName
        Specifies the name of the virtual machine to be retrieved.
    .PARAMETER AllVMs
        Switch to indicate to get all the virtual machines network interfaces on the hypervisor host.
    .PARAMETER HostVmNic
        When true, displays Port Profiles of Host VNics. Otherwise displays Port Profiles of Vm VNics.
    .EXAMPLE
        Get-SdnVMNetworkAdapterPortProfile -VMName 'VM01'
    .EXAMPLE
        Get-SdnVMNetworkAdapterPortProfile -AllVMs
    #>

    [CmdletBinding(DefaultParameterSetName = 'SingleVM')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'SingleVM')]
        [System.String]$VMName,

        [Parameter(Mandatory = $true, ParameterSetName = 'AllVMs')]
        [Switch]$AllVMs,

        [Parameter(ParameterSetName = 'SingleVM', Mandatory = $false)]
        [Parameter(ParameterSetName = 'AllVMs', Mandatory = $false)]
        [switch]$HostVmNic
    )

    [System.Guid]$portProfileFeatureId = "9940cd46-8b06-43bb-b9d5-93d50381fd56"

    try {
        if ($null -eq (Get-Module -Name Hyper-V)) {
            Import-Module -Name Hyper-V -Force
        }

        $arrayList = [System.Collections.ArrayList]::new()

        if ($AllVMs) {
            $netAdapters = Get-VMNetworkAdapter -All | Where-Object { $_.IsManagementOs -eq $HostVmNic }
        }
        else {
            $netAdapters = Get-VMNetworkAdapter -VMName $VMName | Where-Object { $_.IsManagementOs -eq $HostVmNic }
        }

        foreach ($adapter in $netAdapters | Where-Object { $_.IsManagementOs -eq $false }) {
            "Enumerating port features and data for adapter {0}" -f $adapter.MacAddress | Trace-Output -Level:Verbose
            $currentProfile = Get-VMSwitchExtensionPortFeature -FeatureId $portProfileFeatureId -VMNetworkAdapter $adapter
            if ($null -eq $currentProfile) {
                "{0} attached to {1} does not have a port profile" -f $adapter.MacAddress, $adapter.VMName | Trace-Output -Level:Warning
                continue
            }

            $object = [PSCustomObject]@{
                VMName      = $adapter.VMName
                Name        = $adapter.Name
                MacAddress  = $adapter.MacAddress
                ProfileId   = $currentProfile.SettingData.ProfileId
                ProfileData = $currentProfile.SettingData.ProfileData
            }

            $portData = (Get-VMSwitchExtensionPortData -VMNetworkAdapter $adapter)

            # we will typically see multiple port data values for each adapter, however the deviceid should be the same across all of the objects
            # defensive coding in place for situation where vm is not in proper state and this portdata is null
            if ($portData) {
                $object | Add-Member -MemberType NoteProperty -Name 'PortId' -Value $portData[0].data.deviceid
            }
            else {
                $object | Add-Member -MemberType NoteProperty -Name 'PortId' -Value $null
            }

            [void]$arrayList.Add($object)
        }

        return ($arrayList | Sort-Object -Property Name)
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Set-SdnVMNetworkAdapterPortProfile {
    <#
    .SYNOPSIS
        Configures the port profile applied to the virtual machine network interfaces.
    .PARAMETER VMName
        Specifies the name of the virtual machine.
    .PARAMETER MacAddress
        Specifies the MAC address of the VM network adapter.
    .PARAMETER ProfileId
        The InstanceID of the Network Interface taken from Network Controller.
    .PARAMETER ProfileData
        1 = VfpEnabled, 2 = VfpDisabled (usually in the case of Mux). If ommited, defaults to 1.
    .PARAMETER HyperVHost
        Type the NetBIOS name, an IP address, or a fully qualified domain name of the computer that is hosting the virtual machine.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        Set-SdnVMNetworkAdapterPortProfile -VMName 'TestVM01' -MacAddress 001DD826100E
    #>

    [CmdletBinding(DefaultParameterSetName = 'Local')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Remote')]
        [System.String]$VMName,

        [Parameter(Mandatory = $true, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Remote')]
        [System.String]$MacAddress,

        [Parameter(Mandatory = $true, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Remote')]
        [System.Guid]$ProfileId,

        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.Int16]$ProfileData = 1,

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.String]$HyperVHost,

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        switch ($PSCmdlet.ParameterSetName) {
            'Remote' {
                Invoke-PSRemoteCommand -ComputerName $HyperVHost -Credential $Credential -ScriptBlock {
                    Set-VMNetworkAdapterPortProfile -VMName $using:VMName -MacAddress $using:MacAddress -ProfileId $using:ProfileId -ProfileData $using:ProfileData
                }
            }
            'Local' {
                Set-VMNetworkAdapterPortProfile -VMName $VMName -MacAddress $MacAddress -ProfileId $ProfileId -ProfileData $ProfileData
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Test-SdnProviderAddressConnectivity {
    <#
    .SYNOPSIS
        Tests whether jumbo packets can be sent between the provider addresses on the current host to the remote provider addresses defined.
    .PARAMETER ProviderAddress
        The IP address assigned to a hidden network adapter in a non-default network compartment.
    .EXAMPLE
        PS> Test-SdnProviderAddressConnectivity -ProviderAddress (Get-SdnProviderAddress -ComputerName 'Server01','Server02')
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ProviderAddress
    )

    $maxEncapOverhead = 160
    $defaultMTU = 1500
    $icmpHeader = 28

    $jumboPacket = ($maxEncapOverhead + $defaultMTU) - $icmpHeader
    $standardPacket = $defaultMTU - $icmpHeader

    try {
        $arrayList = [System.Collections.ArrayList]::new()

        $sourceProviderAddress = (Get-ProviderAddress).ProviderAddress
        if ($null -eq $sourceProviderAddress) {
            "No provider addresses returned on {0}" -f $env:COMPUTERNAME | Trace-Output -Level:Exception
            return
        }

        $compartmentId = (Get-NetCompartment | Where-Object { $_.CompartmentDescription -ieq 'PAhostVNic' }).CompartmentId
        if ($null -eq $compartmentId) {
            "No compartment returned on {0} that matches description PAhostVNic" -f $env:COMPUTERNAME | Trace-Output -Level:Exception
            return
        }

        foreach ($srcAddress in $sourceProviderAddress) {
            if ($srcAddress -ilike "169.*") {
                # if the PA address is an APIPA, it's an indication that host has been added to SDN data plane, however no tenant workloads have yet been provisioned onto the host
                "Skipping validation of {0} as it's an APIPA address" -f $srcAddress | Trace-Output -Level:Warning
                continue
            }

            foreach ($dstAddress in $ProviderAddress) {
                if ($dstAddress -ilike "169.*") {
                    # if the PA address is an APIPA, it's an indication that host has been added to SDN data plane, however no tenant workloads have yet been provisioned onto the host
                    "Skipping validation of {0} as it's an APIPA address" -f $dstAddress | Trace-Output -Level:Warning
                    continue
                }

                $results = Test-Ping -DestinationAddress $dstAddress -SourceAddress $srcAddress -CompartmentId $compartmentId -BufferSize $jumboPacket, $standardPacket -DontFragment
                [void]$arrayList.Add($results)
            }
        }

        return $arrayList
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
