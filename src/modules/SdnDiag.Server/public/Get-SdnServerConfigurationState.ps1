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

    $currentErrorActionPreference = $ErrorActionPreference
    $ProgressPreference = 'SilentlyContinue'
    $ErrorActionPreference = 'SilentlyContinue'
    $FormatEnumerationLimit = -1

    try {
        $config = Get-SdnModuleConfiguration -Role:Server
        [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath "ConfigState"
        [System.IO.FileInfo]$regDir = Join-Path -Path $OutputDirectory.FullName -ChildPath "Registry"

        "Collect configuration state details for role {0}" -f $config.Name | Trace-Output

        if (-NOT (Initialize-DataCollection -Role:Server -FilePath $OutputDirectory.FullName -MinimumMB 100)) {
            "Unable to initialize environment for data collection" | Trace-Output -Level:Exception
            return
        }

        Export-RegistryKeyConfigDetails -Path $config.properties.regKeyPaths -OutputDirectory $regDir.FullName
        Get-GeneralConfigurationState -OutputDirectory $OutputDirectory.FullName

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
        Get-SdnVfpVmSwitchPort | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnVfpVmSwitchPort' -FileType json

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

        # Gather Hyper-V network details
        "Gathering hyper-v configuration details" | Trace-Output -Level:Verbose
        Get-VM | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VM' -FileType csv
        Get-PACAMapping | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-PACAMapping' -FileType txt -Format Table
        Get-ProviderAddress | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-ProviderAddress' -FileType txt -Format Table
        Get-CustomerRoute | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-CustomerRoute' -FileType txt -Format Table
        Get-NetAdapterVPort | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetAdapterVPort' -FileType txt -Format Table
        Get-NetAdapterVmqQueue | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetAdapterVmqQueue' -FileType txt -Format Table
        Get-SdnNetAdapterEncapOverheadConfig | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnNetAdapterEncapOverheadConfig' -FileType txt -Format Table
        Get-VMSwitch | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMSwitch' -FileType json
        Get-VMSwitchTeam | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMSwitchTeam' -FileType json
        Get-SdnVMNetworkAdapterPortProfile -AllVMs | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnVMNetworkAdapterPortProfile' -FileType txt -Format Table
        Get-VMNetworkAdapterIsolation | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMNetworkAdapterIsolation' -FileType txt -Format Table
        Get-VMNetworkAdapterVLAN | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMNetworkAdapterVLAN' -FileType txt -Format Table
        Get-VMNetworkAdapterRoutingDomainMapping | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMNetworkAdapterRoutingDomainMapping' -FileType txt -Format Table
        Get-VMSystemSwitchExtensionPortFeature -FeatureId "9940cd46-8b06-43bb-b9d5-93d50381fd56" | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMSystemSwitchExtensionPortFeature' -FileType json
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }

    $ProgressPreference = 'Continue'
    $ErrorActionPreference = $currentErrorActionPreference
}
