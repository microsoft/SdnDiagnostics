function Get-ServerConfigState {
    <#
    .SYNOPSIS
        Outputs a set of configuration state files for the server role.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .EXAMPLE
        PS> Get-ServerConfigState -OutputDirectory "C:\Temp\CSS_SDN"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    $currentErrorActionPreference = $ErrorActionPreference
    $ProgressPreference = 'SilentlyContinue'
    $ErrorActionPreference = 'Ignore'

    try {
        $config = Get-SdnModuleConfiguration -Role:Server
        [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath "ConfigState"
        [System.IO.FileInfo]$regDir = Join-Path -Path $OutputDirectory.FullName -ChildPath "Registry"

        "Collect configuration state details for role {0}" -f $config.Name | Trace-Output

        if (-NOT (Initialize-DataCollection -Role:Server -FilePath $OutputDirectory.FullName -MinimumMB 100)) {
            "Unable to initialize environment for data collection" | Trace-Output -Level:Error
            return
        }

        Export-RegistryKeyConfigDetails -Path $config.properties.regKeyPaths -OutputDirectory $regDir.FullName
        Get-CommonConfigState -OutputDirectory $OutputDirectory.FullName

        # Gather VFP port configuration details
        "Gathering VFP port details" | Trace-Output -Level:Verbose
        foreach ($vm in (Get-WmiObject -na root\virtualization\v2 msvm_computersystem)) {
            foreach ($vma in $vm.GetRelated("Msvm_SyntheticEthernetPort")) {
                foreach ($port in $vma.GetRelated("Msvm_SyntheticEthernetPortSettingData").GetRelated("Msvm_EthernetPortAllocationSettingData").GetRelated("Msvm_EthernetSwitchPort")) {
                    $outputDir = New-Item -Path (Join-Path -Path $OutputDirectory.FullName -ChildPath "VFP\$($vm.ElementName)") -ItemType Directory -Force
                    vfpctrl /list-nat-range /port $($port.Name) | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix 'vfpctrl_list_nat_range' -Name $port.Name -FileType txt
                    vfpctrl /list-rule /port $($port.Name) | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix 'vfpctrl_list_rule' -Name $port.Name -FileType txt
                    vfpctrl /list-mapping /port $($port.Name) | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix 'vfpctrl_list_mapping' -Name $port.Name -FileType txt
                    vfpctrl /list-unified-flow /port $port.Name | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix 'vfpctrl_list_unifiied_flow' -Name $port.Name -FileType txt
                    vfpctrl /get-port-flow-settings /port $($port.Name) | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix 'vfpctrl_get_port_flow_settings' -Name $port.Name -FileType txt
                    vfpctrl /get-port-flow-stats /port $($port.Name) | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix 'vfpctrl_get_port_flow_stats' -Name $port.Name -FileType txt
                    vfpctrl /get-flow-stats /port $($port.Name) | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix 'vfpctrl_get_flow_stats' -Name $port.Name -FileType txt
                    vfpctrl /get-port-state /port $($port.Name) | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix 'vfpctrl_get_port_state' -Name $port.Name -FileType txt

                    Get-SdnVfpPortState -PortName $($port.Name) | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix 'Get-SdnVfpPortState' -Name $port.Name -FileType json
                }
            }
        }

        vfpctrl /list-vmswitch-port | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'vfpctrl_list-vmswitch-port' -FileType txt
        Get-SdnVfpVmSwitchPort | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnVfpVmSwitchPort' -FileType json -Depth 3

        # Gather OVSDB databases
        "Gathering ovsdb database output" | Trace-Output -Level:Verbose
        ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_vtep | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'ovsdb_vtep' -FileType txt
        ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_firewall | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'ovsdb_firewall' -FileType txt
        ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_service_insertion | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'ovsdb_serviceinsertion' -FileType txt

        Get-SdnOvsdbAddressMapping | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnOvsdbAddressMapping' -FileType json
        Get-SdnOvsdbFirewallRule | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnOvsdbFirewallRule' -FileType json
        Get-SdnOvsdbGlobalTable | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnOvsdbGlobalTable' -FileType json
        Get-SdnOvsdbPhysicalPort | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnOvsdbPhysicalPort' -FileType json
        Get-SdnOvsdbUcastMacRemoteTable | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnOvsdbUcastMacRemoteTable' -FileType json

        # Get virtual machine details
        "Gathering virtual machine configuration details" | Trace-Output -Level:Verbose
        $vm = Get-VM
        if ($vm) {
            $vmRootDir = New-Item -Path (Join-Path -Path $OutputDirectory.FullName -ChildPath "VM") -ItemType Directory -Force

            $vm | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VM' -FileType csv
            $vm | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VM' -FileType json
            $vm | ForEach-Object {
                $prefix = $_.Name.ToString().Replace(" ", "_").Trim()
                $_ | Get-VMNetworkAdapter | Export-ObjectToFile -FilePath $vmRootDir.FullName -Prefix $prefix -Name 'Get-VMNetworkAdapter' -FileType json
                $_ | Get-VMNetworkAdapterAcl | Export-ObjectToFile -FilePath $vmRootDir.FullName -Prefix $prefix -Name 'Get-VMNetworkAdapterAcl' -FileType json
                $_ | Get-VMNetworkAdapterExtendedAcl | Export-ObjectToFile -FilePath $vmRootDir.FullName -Prefix $prefix -Name 'Get-VMNetworkAdapterExtendedAcl' -FileType json
                $_ | Get-VMNetworkAdapterIsolation | Export-ObjectToFile -FilePath $vmRootDir.FullName -Prefix $prefix -Name 'Get-VMNetworkAdapterIsolation' -FileType json
                $_ | Get-VMNetworkAdapterRoutingDomainMapping | Export-ObjectToFile -FilePath $vmRootDir.FullName -Prefix $prefix -Name 'Get-VMNetworkAdapterRoutingDomainMapping' -FileType json
                $_ | Get-VMNetworkAdapterTeamMapping | Export-ObjectToFile -FilePath $vmRootDir.FullName -Prefix $prefix -Name 'Get-VMNetworkAdapterTeamMapping' -FileType json
                $_ | Get-VMNetworkAdapterVLAN | Export-ObjectToFile -FilePath $vmRootDir.FullName -Prefix $prefix -Name 'Get-VMNetworkAdapterVLAN' -FileType json
            }
        }

        # Gather Hyper-V network details
        "Gathering Hyper-V network configuration details" | Trace-Output -Level:Verbose
        Get-NetAdapterVPort | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetAdapterVPort' -FileType txt -Format Table
        Get-NetAdapterVmqQueue | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetAdapterVmqQueue' -FileType txt -Format Table
        Get-SdnNetAdapterEncapOverheadConfig | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnNetAdapterEncapOverheadConfig' -FileType txt -Format Table
        Get-SdnVMNetworkAdapterPortProfile -AllVMs | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnVMNetworkAdapterPortProfile' -FileType txt -Format Table
        Get-VMNetworkAdapterIsolation | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMNetworkAdapterIsolation' -FileType txt -Format Table
        Get-VMNetworkAdapterVLAN | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMNetworkAdapterVLAN' -FileType txt -Format Table
        Get-VMNetworkAdapterRoutingDomainMapping | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMNetworkAdapterRoutingDomainMapping' -FileType txt -Format Table
        Get-VMSystemSwitchExtensionPortFeature -FeatureId "9940cd46-8b06-43bb-b9d5-93d50381fd56" | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMSystemSwitchExtensionPortFeature' -FileType json

        Get-VMSwitchTeam | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMSwitchTeam' -FileType txt -Format List
        $vmSwitch = Get-VMSwitch
        if ($vmSwitch) {
            $vmSwitchRootDir = New-Item -Path (Join-Path -Path $OutputDirectory.FullName -ChildPath "VMSwitch") -ItemType Directory -Force

            $vmSwitch | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMSwitch' -FileType json
            $vmSwitch | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMSwitch' -FileType txt -Format List
            $vmSwitch | ForEach-Object {
                $prefix = $_.Name.ToString().Replace(" ", "_").Trim()
                $_ | Get-VMSwitchExtension | Export-ObjectToFile -FilePath $vmSwitchRootDir.FullName -Prefix $prefix -Name 'Get-VMSwitchExtension' -FileType json
                $_ | Get-VMSwitchExtensionSwitchData | Export-ObjectToFile -FilePath $vmSwitchRootDir.FullName -Prefix $prefix -Name 'Get-VMSwitchExtensionSwitchData' -FileType json
                $_ | Get-VMSwitchExtensionSwitchFeature | Export-ObjectToFile -FilePath $vmSwitchRootDir.FullName -Prefix $prefix -Name 'Get-VMSwitchExtensionSwitchFeature' -FileType json
                $_ | Get-VMSwitchTeam | Export-ObjectToFile -FilePath $vmSwitchRootDir.FullName -Prefix $prefix -Name 'Get-VMSwitchTeam' -FileType json
            }
        }

        # add fault tolerance for hnvdiagnostics commands that do not have [CmdletBinding()]
        # and will ignore the ErrorActionPreference resulting in a terminating exception
        $hnvDiag = @(
            "Get-PACAMapping",
            "Get-CustomerRoute",
            "Get-ProviderAddress"
        )
        $hnvDiag | ForEach-Object {
            try {
                $cmd = $_
                Invoke-Expression -Command $cmd | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name $cmd -FileType txt -Format Table
            }
            catch {
                "Failed to execute {0}" -f $cmd | Trace-Output -Level:Error
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }

    $ProgressPreference = 'Continue'
    $ErrorActionPreference = $currentErrorActionPreference
}
