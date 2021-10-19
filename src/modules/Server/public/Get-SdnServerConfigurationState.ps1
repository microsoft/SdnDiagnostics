# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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

        if (!(Initialize-DataCollection -Role:Server -FilePath $OutputDirectory.FullName -MinimumMB 100)) {
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
                }
            }
        }

        vfpctrl /list-vmswitch-port | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'vfpctrl_list-vmswitch-port' -FileType json
        Get-SdnVfpVmSwitchPort | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnVfpVmSwitchPort' -FileType csv

        # Gather OVSDB databases
        "Gathering ovsdb database output" | Trace-Output -Level:Verbose
        ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_vtep | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'ovsdb_vtep' -FileType txt
        ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_firewall | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'ovsdb_firewall' -FileType txt
        ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_service_insertion | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'ovsdb_serviceinsertion' -FileType txt
        ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_vtep -f json -pretty | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'ovsdb_vtep' -FileType json
        ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_firewall -f json -pretty | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'ovsdb_firewall' -FileType json
        ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_service_insertion -f json -pretty | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'ovsdb_serviceinsertion' -FileType json

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
        Get-NetworkInterfaceEncapOverheadSetting | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetworkInterfaceEncapOverheadSetting' -FileType txt -Format Table
        Get-VMSwitch | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMSwitch' -FileType txt -Format List
        Get-VMSwitchTeam | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMSwitchTeam' -FileType txt -Format List
        Get-VMNetworkAdapterPortProfile -AllVMs | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMNetworkAdapterPortProfile' -FileType txt -Format Table
        Get-VMNetworkAdapterIsolation | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMNetworkAdapterIsolation' -FileType txt -Format Table
        Get-VMNetworkAdapterRoutingDomainMapping | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMNetworkAdapterRoutingDomainMapping' -FileType txt -Format Table

        Get-GeneralConfigurationState -OutputDirectory $OutputDirectory.FullName
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }

    $ProgressPreference = 'Continue'
}
