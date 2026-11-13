# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# ==============================
#     Collector Definitions
# ==============================

$script:structuredDiagnosticCollectorCatalog = @{
    Groups = @(
        @{
            Id = 'Host'
            TimeoutSeconds = 600
            Collectors = @(
                @{ Id = 'Get-ComputerInfo'; RelativePath = 'Host\Get-ComputerInfo.json'; Collect = { Get-ComputerInfo -ErrorAction Stop } }
                @{ Id = 'Get-Date'; RelativePath = 'Host\Get-Date.json'; Collect = { $localTime = Get-Date -ErrorAction Stop; [PSCustomObject]@{ LocalTime = $localTime.ToString('yyyy-MM-dd HH:mm:ss zzz'); UtcTime = $localTime.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'") } } }
                @{ Id = 'Get-TimeZone'; RelativePath = 'Host\Get-TimeZone.json'; Collect = { Get-TimeZone -ErrorAction Stop } }
                @{ Id = 'Get-CimInstance-Win32_OperatingSystem'; RelativePath = 'Host\Get-CimInstance-Win32_OperatingSystem.json'; Collect = { Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop } }
                @{ Id = 'Get-CimInstance-Win32_Processor'; RelativePath = 'Host\Get-CimInstance-Win32_Processor.json'; Collect = { Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop } }
                @{ Id = 'systeminfo'; Kind = 'Text'; RelativePath = 'Host\systeminfo.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName systeminfo.exe } }
                @{ Id = 'Get-Service'; RelativePath = 'Host\Get-Service.json'; Collect = { Get-Service -Name * -ErrorAction Stop | Select-Object -Property Name, @{ Name = 'StartType'; Expression = { [string]$_.StartType } }, @{ Name = 'Status'; Expression = { [string]$_.Status } } } }
                @{ Id = 'Get-WindowsDriver'; RelativePath = 'Host\Get-WindowsDriver.json'; Collect = { Get-WindowsDriver -Online -All -ErrorAction Stop } }
                @{ Id = 'Get-WindowsEdition'; RelativePath = 'Host\Get-WindowsEdition.json'; Collect = { Get-WindowsEdition -Online -ErrorAction Stop } }
                @{ Id = 'Get-WindowsOptionalFeature'; RelativePath = 'Host\Get-WindowsOptionalFeature.json'; Collect = { Get-WindowsOptionalFeature -Online -ErrorAction Stop } }
                @{ Id = 'Get-HotFix'; RelativePath = 'Host\Get-HotFix.json'; Collect = { Get-HotFix -ErrorAction Stop | Sort-Object -Property InstalledOn } }
                @{ Id = 'Get-PnpDevice'; RelativePath = 'Host\Get-PnpDevice.json'; Collect = { Get-PnpDevice -ErrorAction Stop | Select-Object -Property Class, Status, InstanceId, FriendlyName } }
                # Allowlist properties: raw Process objects expose StartInfo.EnvironmentVariables, which on Windows PowerShell returns the collector's own environment.
                @{ Id = 'Get-Process'; RelativePath = 'Host\Get-Process.json'; Collect = { Get-Process -ErrorAction Stop | Select-Object -Property Id, ProcessName, SessionId, Path, Company, ProductVersion, FileVersion, @{ Name = 'StartTime'; Expression = { try { ([DateTimeOffset]$_.StartTime).UtcDateTime.ToString('o') } catch { $null } } }, CPU, HandleCount, @{ Name = 'ThreadCount'; Expression = { @($_.Threads).Count } }, WorkingSet64, PrivateMemorySize64, VirtualMemorySize64, PagedMemorySize64, NonpagedSystemMemorySize64, @{ Name = 'PriorityClass'; Expression = { try { [string]$_.PriorityClass } catch { $null } } }, Responding } }
                @{ Id = 'Copy-NetworkSetupLogs'; Kind = 'FileSet'; RequiresLogs = $true; RelativePath = 'Host\SetupLogs'; Collect = { param($outputRoot) Copy-StructuredDiagnosticSetupLogs -OutputRoot $outputRoot } }
            )
        }
        @{
            Id = 'NetAdapter'
            TimeoutSeconds = 600
            Collectors = @(
                @{ Id = 'Get-NetAdapter'; RelativePath = 'NetAdapter\Get-NetAdapter.json'; Collect = { Get-NetAdapter -IncludeHidden -ErrorAction Stop } }
                @{ Id = 'Get-NetAdapterStatistics'; Kind = 'FileSet'; RelativePath = 'NetAdapter\Get-NetAdapterStatistics.json'; Collect = { param($outputRoot, $format) Export-StructuredDiagnosticNetAdapterStatistics -OutputRoot $outputRoot -Format $format } }
                @{ Id = 'Get-NetAdapterAdvancedProperty'; RelativePath = 'NetAdapter\Get-NetAdapterAdvancedProperty.json'; Collect = { Get-NetAdapterAdvancedProperty -AllProperties -IncludeHidden -ErrorAction Stop } }
                @{ Id = 'Get-NetAdapterBinding'; RelativePath = 'NetAdapter\Get-NetAdapterBinding.json'; Collect = { Get-NetAdapterBinding -AllBindings -IncludeHidden -ErrorAction Stop } }
                @{ Id = 'Get-NetAdapterChecksumOffload'; RelativePath = 'NetAdapter\Get-NetAdapterChecksumOffload.json'; Collect = { Get-NetAdapterChecksumOffload -IncludeHidden -ErrorAction Stop } }
                @{ Id = 'Get-NetAdapterLso'; RelativePath = 'NetAdapter\Get-NetAdapterLso.json'; Collect = { Get-NetAdapterLso -IncludeHidden -ErrorAction Stop } }
                @{ Id = 'Get-NetAdapterRss'; RelativePath = 'NetAdapter\Get-NetAdapterRss.json'; Collect = { Get-NetAdapterRss -IncludeHidden -ErrorAction Stop } }
                @{ Id = 'Get-NetAdapterEncapsulatedPacketTaskOffload'; RelativePath = 'NetAdapter\Get-NetAdapterEncapsulatedPacketTaskOffload.json'; Collect = { Get-NetAdapterEncapsulatedPacketTaskOffload -IncludeHidden -ErrorAction Stop } }
                @{ Id = 'Get-NetAdapterHardwareInfo'; RelativePath = 'NetAdapter\Get-NetAdapterHardwareInfo.json'; Collect = { Get-NetAdapterHardwareInfo -IncludeHidden -ErrorAction Stop } }
                @{ Id = 'Get-NetAdapterIPsecOffload'; RelativePath = 'NetAdapter\Get-NetAdapterIPsecOffload.json'; Collect = { Get-NetAdapterIPsecOffload -IncludeHidden -ErrorAction Stop } }
                @{ Id = 'Get-NetAdapterPowerManagement'; RelativePath = 'NetAdapter\Get-NetAdapterPowerManagement.json'; Collect = { Get-NetAdapterPowerManagement -IncludeHidden -ErrorAction Stop } }
                @{ Id = 'Get-NetAdapterQos'; RelativePath = 'NetAdapter\Get-NetAdapterQos.json'; Collect = { Get-NetAdapterQos -IncludeHidden -ErrorAction Stop } }
                @{ Id = 'Get-NetAdapterRdma'; RelativePath = 'NetAdapter\Get-NetAdapterRdma.json'; Collect = { Get-NetAdapterRdma -IncludeHidden -ErrorAction Stop } }
                @{ Id = 'Get-NetAdapterPacketDirect'; RelativePath = 'NetAdapter\Get-NetAdapterPacketDirect.json'; Collect = { Get-NetAdapterPacketDirect -IncludeHidden -ErrorAction Stop } }
                @{ Id = 'Get-NetAdapterRsc'; RelativePath = 'NetAdapter\Get-NetAdapterRsc.json'; Collect = { Get-NetAdapterRsc -IncludeHidden -ErrorAction Stop } }
                @{ Id = 'Get-NetAdapterSriov'; RelativePath = 'NetAdapter\Get-NetAdapterSriov.json'; Collect = { Get-NetAdapterSriov -IncludeHidden -ErrorAction Stop } }
                @{ Id = 'Get-NetAdapterSriovVf'; RelativePath = 'NetAdapter\Get-NetAdapterSriovVf.json'; Collect = { Get-NetAdapterSriovVf -IncludeHidden -ErrorAction Stop } }
                @{ Id = 'Get-NetAdapterUso'; RelativePath = 'NetAdapter\Get-NetAdapterUso.json'; Collect = { Get-NetAdapterUso -IncludeHidden -ErrorAction Stop } }
                @{ Id = 'Get-NetAdapterVmq'; RelativePath = 'NetAdapter\Get-NetAdapterVmq.json'; Collect = { Get-NetAdapterVmq -IncludeHidden -ErrorAction Stop } }
                @{ Id = 'Get-NetAdapterVmqQueue'; RelativePath = 'NetAdapter\Get-NetAdapterVmqQueue.json'; Collect = { Get-NetAdapterVmqQueue -IncludeHidden -ErrorAction Stop } }
                @{ Id = 'Get-NetAdapterVPort'; RelativePath = 'NetAdapter\Get-NetAdapterVPort.json'; Collect = { Get-NetAdapterVPort -IncludeHidden -ErrorAction Stop } }
                @{ Id = 'nmbind'; Kind = 'Text'; RelativePath = 'NetAdapter\nmbind.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName nmbind.exe } }
            )
        }
        @{
            Id = 'VM'
            TimeoutSeconds = 600
            Collectors = @(
                @{ Id = 'Get-VM'; RelativePath = 'VM\Get-VM.json'; Collect = { param($context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'VirtualMachines' -Collect { Get-VM -ErrorAction Stop } } }
                @{ Id = 'Get-VMBios'; RelativePath = 'VM\Get-VMBios.json'; Collect = { param($context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'VirtualMachines' -Collect { Get-VM -ErrorAction Stop } | Where-Object Generation -eq 1 | Get-VMBios -ErrorAction Stop } }
                @{ Id = 'Get-VMFirmware'; RelativePath = 'VM\Get-VMFirmware.json'; Collect = { param($context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'VirtualMachines' -Collect { Get-VM -ErrorAction Stop } | Where-Object Generation -eq 2 | Get-VMFirmware -ErrorAction Stop } }
                @{ Id = 'Get-VMProcessor'; RelativePath = 'VM\Get-VMProcessor.json'; Collect = { param($context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'VirtualMachines' -Collect { Get-VM -ErrorAction Stop } | Get-VMProcessor -ErrorAction Stop } }
                @{ Id = 'Get-VMMemory'; RelativePath = 'VM\Get-VMMemory.json'; Collect = { param($context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'VirtualMachines' -Collect { Get-VM -ErrorAction Stop } | Get-VMMemory -ErrorAction Stop } }
                @{ Id = 'Get-VMVideo'; RelativePath = 'VM\Get-VMVideo.json'; Collect = { param($context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'VirtualMachines' -Collect { Get-VM -ErrorAction Stop } | Get-VMVideo -ErrorAction Stop } }
                @{ Id = 'Get-VMHardDiskDrive'; RelativePath = 'VM\Get-VMHardDiskDrive.json'; Collect = { param($context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'VirtualMachines' -Collect { Get-VM -ErrorAction Stop } | Get-VMHardDiskDrive -ErrorAction Stop } }
                @{ Id = 'Get-VMComPort'; RelativePath = 'VM\Get-VMComPort.json'; Collect = { param($context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'VirtualMachines' -Collect { Get-VM -ErrorAction Stop } | Get-VMComPort -ErrorAction Stop } }
                @{ Id = 'Get-VMSecurity'; RelativePath = 'VM\Get-VMSecurity.json'; Collect = { param($context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'VirtualMachines' -Collect { Get-VM -ErrorAction Stop } | Get-VMSecurity -ErrorAction Stop } }
            )
        }
        @{
            Id = 'TcpIp'
            TimeoutSeconds = 600
            Collectors = @(
                @{ Id = 'Get-NetIPAddress'; RelativePath = 'TcpIp\Get-NetIPAddress.json'; Collect = { Get-NetIPAddress -ErrorAction Stop } }
                @{ Id = 'Get-NetIPInterface'; RelativePath = 'TcpIp\Get-NetIPInterface.json'; Collect = { Get-NetIPInterface -IncludeAllCompartments -ErrorAction Stop } }
                @{ Id = 'Get-NetNeighbor'; RelativePath = 'TcpIp\Get-NetNeighbor.json'; Collect = { Get-NetNeighbor -ErrorAction Stop } }
                @{ Id = 'Get-NetRoute'; RelativePath = 'TcpIp\Get-NetRoute.json'; Collect = { Get-NetRoute -IncludeAllCompartments -ErrorAction Stop | ForEach-Object { $route = $_ | Select-Object -Property * -ExcludeProperty PreferredLifetime, ValidLifetime; $route | Add-Member -NotePropertyName PreferredLifetime -NotePropertyValue ([string]$_.PreferredLifetime); $route | Add-Member -NotePropertyName ValidLifetime -NotePropertyValue ([string]$_.ValidLifetime); $route } } }
                @{ Id = 'Get-NetIPv4Protocol'; RelativePath = 'TcpIp\Get-NetIPv4Protocol.json'; Collect = { Get-NetIPv4Protocol -ErrorAction Stop } }
                @{ Id = 'Get-NetIPv6Protocol'; RelativePath = 'TcpIp\Get-NetIPv6Protocol.json'; Collect = { Get-NetIPv6Protocol -ErrorAction Stop } }
                @{ Id = 'Get-NetOffloadGlobalSetting'; RelativePath = 'TcpIp\Get-NetOffloadGlobalSetting.json'; Collect = { Get-NetOffloadGlobalSetting -ErrorAction Stop } }
                @{ Id = 'Get-NetPrefixPolicy'; RelativePath = 'TcpIp\Get-NetPrefixPolicy.json'; Collect = { Get-NetPrefixPolicy -ErrorAction Stop } }
                @{ Id = 'Get-NetTCPConnection'; RelativePath = 'TcpIp\Get-NetTCPConnection.json'; Collect = { Get-NetTCPConnection -ErrorAction Stop } }
                @{ Id = 'Get-NetTCPSetting'; RelativePath = 'TcpIp\Get-NetTCPSetting.json'; Collect = { Get-NetTCPSetting -ErrorAction Stop } }
                @{ Id = 'Get-NetTransportFilter'; RelativePath = 'TcpIp\Get-NetTransportFilter.json'; Collect = { Get-NetTransportFilter -ErrorAction Stop } }
                @{ Id = 'Get-NetUDPEndpoint'; RelativePath = 'TcpIp\Get-NetUDPEndpoint.json'; Collect = { Get-NetUDPEndpoint -ErrorAction Stop } }
                @{ Id = 'Get-NetUDPSetting'; RelativePath = 'TcpIp\Get-NetUDPSetting.json'; Collect = { Get-NetUDPSetting -ErrorAction Stop } }
                @{ Id = 'Get-NetCompartment'; RelativePath = 'TcpIp\Get-NetCompartment.json'; Collect = { Get-NetCompartment -ErrorAction Stop } }
                @{ Id = 'Get-NetConnectionProfile'; RelativePath = 'TcpIp\Get-NetConnectionProfile.json'; Collect = { Get-NetConnectionProfile -ErrorAction Stop } }
                @{ Id = 'ipconfig-all'; Kind = 'Text'; RelativePath = 'TcpIp\ipconfig-all.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName ipconfig.exe -ArgumentList '/all' } }
                @{ Id = 'ipconfig-allcompartments-all'; Kind = 'Text'; RelativePath = 'TcpIp\ipconfig-allcompartments-all.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName ipconfig.exe -ArgumentList '/allcompartments', '/all' } }
                @{ Id = 'arp-a'; Kind = 'Text'; RelativePath = 'TcpIp\arp-a.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName arp.exe -ArgumentList '-a' } }
                @{ Id = 'netstat-nasert'; Kind = 'Text'; RelativePath = 'TcpIp\netstat-nasert.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName netstat.exe -ArgumentList '-nasert' } }
                @{ Id = 'netstat-an'; Kind = 'Text'; RelativePath = 'TcpIp\netstat-an.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName netstat.exe -ArgumentList '-an' } }
                @{ Id = 'netstat-xan'; Kind = 'Text'; RelativePath = 'TcpIp\netstat-xan.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName netstat.exe -ArgumentList '-xan' } }
                @{ Id = 'netsh-dump'; Kind = 'Text'; RelativePath = 'TcpIp\netsh-dump.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName netsh.exe -ArgumentList 'dump' } }
                @{ Id = 'netsh-ipv4-show-icmpstats'; Kind = 'Text'; RelativePath = 'TcpIp\netsh-ipv4-show-icmpstats.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName netsh.exe -ArgumentList 'interface', 'ipv4', 'show', 'icmpstats' } }
                @{ Id = 'netsh-ipv4-show-ipstats'; Kind = 'Text'; RelativePath = 'TcpIp\netsh-ipv4-show-ipstats.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName netsh.exe -ArgumentList 'interface', 'ipv4', 'show', 'ipstats' } }
                @{ Id = 'netsh-ipv4-show-tcpstats'; Kind = 'Text'; RelativePath = 'TcpIp\netsh-ipv4-show-tcpstats.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName netsh.exe -ArgumentList 'interface', 'ipv4', 'show', 'tcpstats' } }
                @{ Id = 'netsh-ipv4-show-udpstats'; Kind = 'Text'; RelativePath = 'TcpIp\netsh-ipv4-show-udpstats.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName netsh.exe -ArgumentList 'interface', 'ipv4', 'show', 'udpstats' } }
                @{ Id = 'netsh-ipv4-show-subinterfaces'; Kind = 'Text'; RelativePath = 'TcpIp\netsh-ipv4-show-subinterfaces.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName netsh.exe -ArgumentList 'interface', 'ipv4', 'show', 'subinterfaces', 'level=verbose' } }
                @{ Id = 'netsh-ipv6-show-ipstats'; Kind = 'Text'; RelativePath = 'TcpIp\netsh-ipv6-show-ipstats.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName netsh.exe -ArgumentList 'interface', 'ipv6', 'show', 'ipstats' } }
                @{ Id = 'netsh-ipv6-show-tcpstats'; Kind = 'Text'; RelativePath = 'TcpIp\netsh-ipv6-show-tcpstats.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName netsh.exe -ArgumentList 'interface', 'ipv6', 'show', 'tcpstats' } }
                @{ Id = 'netsh-ipv6-show-udpstats'; Kind = 'Text'; RelativePath = 'TcpIp\netsh-ipv6-show-udpstats.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName netsh.exe -ArgumentList 'interface', 'ipv6', 'show', 'udpstats' } }
                @{ Id = 'netsh-ipv6-show-subinterfaces'; Kind = 'Text'; RelativePath = 'TcpIp\netsh-ipv6-show-subinterfaces.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName netsh.exe -ArgumentList 'interface', 'ipv6', 'show', 'subinterfaces', 'level=verbose' } }
                @{ Id = 'netsh-fl48-show-virtualinterfaces'; Kind = 'Text'; RelativePath = 'TcpIp\netsh-fl48-show-virtualinterfaces.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName netsh.exe -ArgumentList 'interface', 'fl48', 'show', 'virtualinterfaces', 'level=verbose' } }
                @{ Id = 'netsh-fl68-show-virtualinterfaces'; Kind = 'Text'; RelativePath = 'TcpIp\netsh-fl68-show-virtualinterfaces.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName netsh.exe -ArgumentList 'interface', 'fl68', 'show', 'virtualinterfaces', 'level=verbose' } }
                @{ Id = 'netsh-trace-show-scenarios'; Kind = 'Text'; RelativePath = 'TcpIp\netsh-trace-show-scenarios.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName netsh.exe -ArgumentList 'trace', 'show', 'scenarios' } }
                @{ Id = 'netsh-trace-show-providers'; Kind = 'Text'; RelativePath = 'TcpIp\netsh-trace-show-providers.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName netsh.exe -ArgumentList 'trace', 'show', 'providers' } }
            )
        }
        @{
            Id = 'Dns'
            TimeoutSeconds = 600
            Collectors = @(
                @{ Id = 'Get-DnsClient'; RelativePath = 'Dns\Get-DnsClient.json'; Collect = { Get-DnsClient -ErrorAction Stop } }
                @{ Id = 'Get-DnsClientServerAddress'; RelativePath = 'Dns\Get-DnsClientServerAddress.json'; Collect = { Get-DnsClientServerAddress -ErrorAction Stop } }
                @{ Id = 'Get-DnsClientCache'; RelativePath = 'Dns\Get-DnsClientCache.json'; Collect = { Get-DnsClientCache -ErrorAction Stop } }
                @{ Id = 'Get-DnsClientGlobalSetting'; RelativePath = 'Dns\Get-DnsClientGlobalSetting.json'; Collect = { Get-DnsClientGlobalSetting -ErrorAction Stop } }
                @{ Id = 'Get-DnsClientNrptGlobal'; RelativePath = 'Dns\Get-DnsClientNrptGlobal.json'; Collect = { Get-DnsClientNrptGlobal -ErrorAction Stop } }
                @{ Id = 'Get-DnsClientNrptPolicy'; RelativePath = 'Dns\Get-DnsClientNrptPolicy.json'; Collect = { Get-DnsClientNrptPolicy -ErrorAction Stop } }
                @{ Id = 'Get-DnsClientNrptRule'; RelativePath = 'Dns\Get-DnsClientNrptRule.json'; Collect = { Get-DnsClientNrptRule -ErrorAction Stop } }
            )
        }
        @{
            Id = 'Nat'
            TimeoutSeconds = 600
            Collectors = @(
                @{ Id = 'Get-NetNat'; RelativePath = 'Nat\Get-NetNat.json'; Collect = { Get-NetNat -ErrorAction Stop } }
                @{ Id = 'Get-NetNatExternalAddress'; RelativePath = 'Nat\Get-NetNatExternalAddress.json'; Collect = { Get-NetNatExternalAddress -ErrorAction Stop } }
                @{ Id = 'Get-NetNatGlobal'; RelativePath = 'Nat\Get-NetNatGlobal.json'; Collect = { Get-NetNatGlobal -ErrorAction Stop } }
                @{ Id = 'Get-NetNatSession'; ExpectedUnavailableFailure = '^The request is not supported\.\s*$'; RelativePath = 'Nat\Get-NetNatSession.json'; Collect = { Get-NetNatSession -ErrorAction Stop } }
                @{ Id = 'Get-NetNatStaticMapping'; RelativePath = 'Nat\Get-NetNatStaticMapping.json'; Collect = { Get-NetNatStaticMapping -ErrorAction Stop } }
            )
        }
        @{
            Id = 'HyperV'
            TimeoutSeconds = 600
            Collectors = @(
                @{ Id = 'Get-VMHost'; RelativePath = 'HyperV\Get-VMHost.json'; Collect = { Get-VMHost -ErrorAction Stop } }
                @{ Id = 'Get-VMHostSupportedVersion'; RelativePath = 'HyperV\Get-VMHostSupportedVersion.json'; Collect = { Get-VMHostSupportedVersion -ErrorAction Stop } }
                @{ Id = 'Get-VMSystemSwitchExtension'; RelativePath = 'HyperV\Get-VMSystemSwitchExtension.json'; Collect = { Get-VMSystemSwitchExtension -ErrorAction Stop } }
                @{ Id = 'Get-VMSystemSwitchExtensionSwitchFeature'; RelativePath = 'HyperV\Get-VMSystemSwitchExtensionSwitchFeature.json'; Collect = { Get-VMSystemSwitchExtensionSwitchFeature -ErrorAction Stop } }
                @{ Id = 'Get-VMSystemSwitchExtensionPortFeature'; RelativePath = 'HyperV\Get-VMSystemSwitchExtensionPortFeature.json'; Collect = { Get-VMSystemSwitchExtensionPortFeature -ErrorAction Stop } }
            )
        }
        @{
            Id = 'Cluster'
            TimeoutSeconds = 600
            Condition = { Test-StructuredDiagnosticClusterAvailable }
            Collectors = @(
                @{ Id = 'Get-Cluster'; ExcludedProperties = @('Cluster', 'SharedVolumeSecurityDescriptor'); RelativePath = 'Cluster\Get-Cluster.json'; Collect = { Get-Cluster -ErrorAction Stop } }
                @{ Id = 'Get-ClusterNode'; ExcludedProperties = @('Cluster'); RelativePath = 'Cluster\Get-ClusterNode.json'; Collect = { Get-ClusterNode -ErrorAction Stop } }
                @{ Id = 'Get-ClusterNetwork'; ExcludedProperties = @('Cluster'); RelativePath = 'Cluster\Get-ClusterNetwork.json'; Collect = { Get-ClusterNetwork -ErrorAction Stop } }
                @{ Id = 'Get-ClusterNetworkInterface'; ExcludedProperties = @('Cluster'); RelativePath = 'Cluster\Get-ClusterNetworkInterface.json'; Collect = { Get-ClusterNetworkInterface -ErrorAction Stop } }
                @{ Id = 'Get-ClusterGroup'; ExcludedProperties = @('Cluster'); RelativePath = 'Cluster\Get-ClusterGroup.json'; Collect = { Get-ClusterGroup -ErrorAction Stop } }
                @{ Id = 'Get-ClusterResource'; ExcludedProperties = @('Cluster'); RelativePath = 'Cluster\Get-ClusterResource.json'; Collect = { param($context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'ClusterResources' -Collect { Get-ClusterResource -ErrorAction Stop } } }
                @{ Id = 'Get-ClusterResourceDependency'; ExcludedProperties = @('Cluster'); RelativePath = 'Cluster\Get-ClusterResourceDependency.json'; Collect = { param($context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'ClusterResources' -Collect { Get-ClusterResource -ErrorAction Stop } | ForEach-Object { $resourceName = $_.Name; $_ | Get-ClusterResourceDependency -ErrorAction Stop | ForEach-Object { $_ | Select-Object -Property *, @{ Name = 'ResourceName'; Expression = { $resourceName } } } } } }
                @{ Id = 'Get-ClusterParameter'; ExcludedProperties = @('Cluster'); RelativePath = 'Cluster\Get-ClusterParameter.json'; Collect = { param($context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'ClusterResources' -Collect { Get-ClusterResource -ErrorAction Stop } | ForEach-Object { $resourceName = $_.Name; $_ | Get-ClusterParameter -ErrorAction Stop | Where-Object { $_.Name -notmatch '(?i)password|secret|token|credential' } | Select-Object -Property *, @{ Name = 'ResourceName'; Expression = { $resourceName } } } } }
                @{ Id = 'Get-ClusterQuorum'; ExcludedProperties = @('Cluster'); RelativePath = 'Cluster\Get-ClusterQuorum.json'; Collect = { Get-ClusterQuorum -ErrorAction Stop } }
                @{ Id = 'Get-ClusterSharedVolume'; ExcludedProperties = @('Cluster'); RelativePath = 'Cluster\Get-ClusterSharedVolume.json'; Collect = { Get-ClusterSharedVolume -ErrorAction Stop } }
                @{ Id = 'Get-ClusterFaultDomain'; ExcludedProperties = @('Cluster'); RelativePath = 'Cluster\Get-ClusterFaultDomain.json'; Collect = { Get-ClusterFaultDomain -ErrorAction Stop } }
                @{ Id = 'Get-ClusterStorageSpacesDirect'; ExcludedProperties = @('Cluster'); RelativePath = 'Cluster\Get-ClusterStorageSpacesDirect.json'; Collect = { Get-ClusterStorageSpacesDirect -ErrorAction Stop } }
            )
        }
        @{
            Id = 'ClusterPerf'
            TimeoutSeconds = 600
            Condition = { Test-StructuredDiagnosticClusterAvailable }
            Collectors = @(
                @{ Id = 'Get-ClusterPerf-NetworkAdapter'; Kind = 'Performance'; ExcludedProperties = @('Cluster', 'PSComputerName'); RelativePath = 'ClusterPerf\Get-ClusterPerf-NetworkAdapter.json'; Collect = { param($timeFrame) Get-NetAdapter -ErrorAction Stop | Get-ClusterPerf -TimeFrame $timeFrame -ErrorAction Stop -NetAdapterSeriesName @('netadapter.bandwidth.inbound', 'netadapter.bandwidth.outbound', 'netadapter.bandwidth.total', 'netadapter.bandwidth.rdma.inbound', 'netadapter.bandwidth.rdma.outbound', 'netadapter.bandwidth.rdma.total') } }
                @{ Id = 'Get-ClusterPerf-ClusterNode'; Kind = 'Performance'; ExcludedProperties = @('Cluster', 'PSComputerName'); RelativePath = 'ClusterPerf\Get-ClusterPerf-ClusterNode.json'; Collect = { param($timeFrame) Get-ClusterNode -Name $env:COMPUTERNAME -ErrorAction Stop | Get-ClusterPerf -TimeFrame $timeFrame -ErrorAction Stop -ClusterNodeSeriesName @('clusternode.cpu.usage', 'clusternode.cpu.usage.guest', 'clusternode.cpu.usage.host', 'clusternode.memory.total', 'clusternode.memory.available', 'clusternode.memory.usage', 'clusternode.memory.usage.guest', 'clusternode.memory.usage.host') } }
                @{ Id = 'Get-ClusterPerf-VHD'; Kind = 'Performance'; ExcludedProperties = @('Cluster', 'PSComputerName'); RelativePath = 'ClusterPerf\Get-ClusterPerf-VHD.json'; Collect = { param($timeFrame, $context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'VirtualMachines' -Collect { Get-VM -ErrorAction Stop } | Get-VMHardDiskDrive -ErrorAction Stop | Get-VHD -ErrorAction Stop | Get-ClusterPerf -TimeFrame $timeFrame -ErrorAction Stop -VHDSeriesName @('vhd.iops.read', 'vhd.iops.write', 'vhd.iops.total', 'vhd.throughput.read', 'vhd.throughput.write', 'vhd.throughput.total', 'vhd.latency.average', 'vhd.size.current', 'vhd.size.maximum') } }
                @{ Id = 'Get-ClusterPerf-VM'; Kind = 'Performance'; ExcludedProperties = @('Cluster', 'PSComputerName'); RelativePath = 'ClusterPerf\Get-ClusterPerf-VM.json'; Collect = { param($timeFrame, $context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'VirtualMachines' -Collect { Get-VM -ErrorAction Stop } | Get-ClusterPerf -TimeFrame $timeFrame -ErrorAction Stop -VMSeriesName @('vm.cpu.usage', 'vm.memory.assigned', 'vm.memory.available', 'vm.memory.maximum', 'vm.memory.minimum', 'vm.memory.pressure', 'vm.memory.startup', 'vm.memory.total') } }
                @{ Id = 'Get-ClusterPerf-VMNetworkAdapter'; Kind = 'Performance'; ExcludedProperties = @('Cluster', 'PSComputerName'); RelativePath = 'ClusterPerf\Get-ClusterPerf-VMNetworkAdapter.json'; Collect = { param($timeFrame, $context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'VirtualMachines' -Collect { Get-VM -ErrorAction Stop } | Get-ClusterPerf -TimeFrame $timeFrame -ErrorAction Stop -VMSeriesName @('vmnetworkadapter.bandwidth.inbound', 'vmnetworkadapter.bandwidth.outbound', 'vmnetworkadapter.bandwidth.total') } }
            )
        }
        @{
            Id = 'VMSwitch'
            TimeoutSeconds = 600
            Collectors = @(
                @{ Id = 'Get-VMSwitch'; RelativePath = 'VMSwitch\Get-VMSwitch.json'; Collect = { param($context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'VirtualSwitches' -Collect { Get-VMSwitch -ErrorAction Stop } } }
                @{ Id = 'Get-VMSwitchExtension'; RelativePath = 'VMSwitch\Get-VMSwitchExtension.json'; Collect = { param($context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'VirtualSwitches' -Collect { Get-VMSwitch -ErrorAction Stop } | Get-VMSwitchExtension -ErrorAction Stop } }
                @{ Id = 'Get-VMSwitchExtensionSwitchData'; RelativePath = 'VMSwitch\Get-VMSwitchExtensionSwitchData.json'; Collect = { param($context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'VirtualSwitches' -Collect { Get-VMSwitch -ErrorAction Stop } | Get-VMSwitchExtensionSwitchData -ErrorAction Stop } }
                @{ Id = 'Get-VMSwitchExtensionSwitchFeature'; RelativePath = 'VMSwitch\Get-VMSwitchExtensionSwitchFeature.json'; Collect = { param($context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'VirtualSwitches' -Collect { Get-VMSwitch -ErrorAction Stop } | Get-VMSwitchExtensionSwitchFeature -ErrorAction Stop } }
                @{ Id = 'Get-VMSwitchTeam'; RelativePath = 'VMSwitch\Get-VMSwitchTeam.json'; Collect = { param($context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'VirtualSwitches' -Collect { Get-VMSwitch -ErrorAction Stop } | Where-Object EmbeddedTeamingEnabled | Get-VMSwitchTeam -ErrorAction Stop } }
                @{ Id = 'Get-VMNetworkAdapterTeamMapping-ManagementOS'; RelativePath = 'VMSwitch\Get-VMNetworkAdapterTeamMapping-ManagementOS.json'; Collect = { Get-VMNetworkAdapterTeamMapping -ManagementOS -ErrorAction Stop } }
                @{ Id = 'nvspinfo-inventory'; Kind = 'Text'; RelativePath = 'VMSwitch\nvspinfo-inventory.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName nvspinfo.exe -ArgumentList '-a', '-i', '-h', '-D', '-p', '-d', '-m', '-q' } }
                @{ Id = 'nvspinfo-bindings'; Kind = 'Text'; RelativePath = 'VMSwitch\nvspinfo-bindings.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName nvspinfo.exe -ArgumentList '-b' } }
            )
        }
        @{
            Id = 'VMNetworkAdapter'
            TimeoutSeconds = 600
            Collectors = @(
                @{ Id = 'Get-VMNetworkAdapter'; RelativePath = 'VMNetworkAdapter\Get-VMNetworkAdapter.json'; Collect = { param($context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'AllVMNetworkAdapters' -Collect { Get-VMNetworkAdapter -All -ErrorAction Stop } } }
                @{ Id = 'Get-VMNetworkAdapter-ManagementOS'; RelativePath = 'VMNetworkAdapter\Get-VMNetworkAdapter-ManagementOS.json'; Collect = { Get-VMNetworkAdapter -ManagementOS -ErrorAction Stop } }
                @{ Id = 'Get-VMNetworkAdapterAcl'; RelativePath = 'VMNetworkAdapter\Get-VMNetworkAdapterAcl.json'; Collect = { param($context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'AllVMNetworkAdapters' -Collect { Get-VMNetworkAdapter -All -ErrorAction Stop } | Get-VMNetworkAdapterAcl -ErrorAction Stop } }
                @{ Id = 'Get-VMNetworkAdapterExtendedAcl'; RelativePath = 'VMNetworkAdapter\Get-VMNetworkAdapterExtendedAcl.json'; Collect = { param($context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'AllVMNetworkAdapters' -Collect { Get-VMNetworkAdapter -All -ErrorAction Stop } | Get-VMNetworkAdapterExtendedAcl -ErrorAction Stop } }
                @{ Id = 'Get-VMNetworkAdapterFailoverConfiguration'; RelativePath = 'VMNetworkAdapter\Get-VMNetworkAdapterFailoverConfiguration.json'; Collect = { Get-VM -ErrorAction Stop | Get-VMNetworkAdapter -ErrorAction Stop | Get-VMNetworkAdapterFailoverConfiguration -ErrorAction Stop } }
                @{ Id = 'Get-VMNetworkAdapterIsolation'; RelativePath = 'VMNetworkAdapter\Get-VMNetworkAdapterIsolation.json'; ExcludedProperties = @('ParentAdapter'); Collect = { param($context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'AllVMNetworkAdapters' -Collect { Get-VMNetworkAdapter -All -ErrorAction Stop } | Get-VMNetworkAdapterIsolation -ErrorAction Stop } }
                @{ Id = 'Get-VMNetworkAdapterRoutingDomainMapping'; RelativePath = 'VMNetworkAdapter\Get-VMNetworkAdapterRoutingDomainMapping.json'; Collect = { param($context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'AllVMNetworkAdapters' -Collect { Get-VMNetworkAdapter -All -ErrorAction Stop } | Get-VMNetworkAdapterRoutingDomainMapping -ErrorAction Stop } }
                @{ Id = 'Get-VMNetworkAdapterTeamMapping'; RelativePath = 'VMNetworkAdapter\Get-VMNetworkAdapterTeamMapping.json'; Collect = { param($context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'AllVMNetworkAdapters' -Collect { Get-VMNetworkAdapter -All -ErrorAction Stop } | Get-VMNetworkAdapterTeamMapping -ErrorAction Stop } }
                @{ Id = 'Get-VMNetworkAdapterVlan'; RelativePath = 'VMNetworkAdapter\Get-VMNetworkAdapterVlan.json'; Collect = { param($context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'AllVMNetworkAdapters' -Collect { Get-VMNetworkAdapter -All -ErrorAction Stop } | Get-VMNetworkAdapterVlan -ErrorAction Stop } }
                @{ Id = 'Get-VMSwitchExtensionPortFeature'; RelativePath = 'VMNetworkAdapter\Get-VMSwitchExtensionPortFeature.json'; Collect = { param($context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'AllVMNetworkAdapters' -Collect { Get-VMNetworkAdapter -All -ErrorAction Stop } | Get-VMSwitchExtensionPortFeature -ErrorAction Stop } }
                @{ Id = 'Get-VMSwitchExtensionPortData'; RelativePath = 'VMNetworkAdapter\Get-VMSwitchExtensionPortData.json'; Collect = { param($context) Get-StructuredDiagnosticCachedValue -Cache $context -Key 'AllVMNetworkAdapters' -Collect { Get-VMNetworkAdapter -All -ErrorAction Stop } | Get-VMSwitchExtensionPortData -ErrorAction Stop } }
            )
        }
        @{
            Id = 'Qos'
            TimeoutSeconds = 600
            Collectors = @(
                @{ Id = 'Get-NetQosDcbxSetting'; RelativePath = 'Qos\Get-NetQosDcbxSetting.json'; Collect = { Get-NetQosDcbxSetting -ErrorAction Stop } }
                @{ Id = 'Get-NetQosFlowControl'; RelativePath = 'Qos\Get-NetQosFlowControl.json'; Collect = { Get-NetQosFlowControl -ErrorAction Stop } }
                @{ Id = 'Get-NetQosPolicy'; RelativePath = 'Qos\Get-NetQosPolicy.json'; Collect = { Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction Stop } }
                @{ Id = 'Get-NetQosTrafficClass'; RelativePath = 'Qos\Get-NetQosTrafficClass.json'; Collect = { Get-NetQosTrafficClass -ErrorAction Stop } }
                @{ Id = 'netsh-lan-show-interface'; Kind = 'Text'; ExpectedUnavailableFailure = '^Command netsh\.exe exited with code 1\.'; RelativePath = 'Qos\netsh-lan-show-interface.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName netsh.exe -ArgumentList 'lan', 'show', 'interface' } }
                @{ Id = 'netsh-lan-show-profile'; Kind = 'Text'; ExpectedUnavailableFailure = '^Command netsh\.exe exited with code 1\.'; RelativePath = 'Qos\netsh-lan-show-profile.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName netsh.exe -ArgumentList 'lan', 'show', 'profile' } }
            )
        }
        @{
            Id = 'Lldp'
            TimeoutSeconds = 600
            Collectors = @(
                @{ Id = 'Get-NetLldpAgent'; RelativePath = 'Lldp\Get-NetLldpAgent.json'; Collect = { Get-NetLldpAgent -ErrorAction Stop } }
            )
        }
        @{
            Id = 'Smb'
            TimeoutSeconds = 600
            Collectors = @(
                @{ Id = 'Get-SmbConnection'; RelativePath = 'Smb\Get-SmbConnection.json'; Collect = { Get-SmbConnection -ErrorAction Stop } }
                @{ Id = 'Get-SmbMapping'; RelativePath = 'Smb\Get-SmbMapping.json'; Collect = { Get-SmbMapping -ErrorAction Stop } }
                @{ Id = 'Get-SmbSession'; RelativePath = 'Smb\Get-SmbSession.json'; Collect = { Get-SmbSession -ErrorAction Stop } }
                @{ Id = 'Get-SmbClientNetworkInterface'; RelativePath = 'Smb\Get-SmbClientNetworkInterface.json'; Collect = { Get-SmbClientNetworkInterface -ErrorAction Stop } }
                @{ Id = 'Get-SmbServerNetworkInterface'; RelativePath = 'Smb\Get-SmbServerNetworkInterface.json'; Collect = { Get-SmbServerNetworkInterface -ErrorAction Stop } }
                @{ Id = 'Get-SmbClientConfiguration'; RelativePath = 'Smb\Get-SmbClientConfiguration.json'; Collect = { Get-SmbClientConfiguration -ErrorAction Stop } }
                @{ Id = 'Get-SmbServerConfiguration'; RelativePath = 'Smb\Get-SmbServerConfiguration.json'; Collect = { Get-SmbServerConfiguration -ErrorAction Stop } }
                @{ Id = 'Get-SmbMultichannelConnection'; RelativePath = 'Smb\Get-SmbMultichannelConnection.json'; Collect = { Get-SmbMultichannelConnection -ErrorAction Stop } }
                @{ Id = 'Get-SmbMultichannelConnection-IncludeNotSelected'; RelativePath = 'Smb\Get-SmbMultichannelConnection-IncludeNotSelected.json'; Collect = { Get-SmbMultichannelConnection -IncludeNotSelected -ErrorAction Stop } }
                @{ Id = 'Get-SmbMultichannelConnection-CSV'; RelativePath = 'Smb\Get-SmbMultichannelConnection-CSV.json'; Collect = { Get-SmbMultichannelConnection -SmbInstance CSV -IncludeNotSelected -ErrorAction Stop } }
                @{ Id = 'Get-SmbMultichannelConnection-SBL'; RelativePath = 'Smb\Get-SmbMultichannelConnection-SBL.json'; Collect = { Get-SmbMultichannelConnection -SmbInstance SBL -IncludeNotSelected -ErrorAction Stop } }
                @{ Id = 'Get-SmbMultichannelConstraint'; RelativePath = 'Smb\Get-SmbMultichannelConstraint.json'; Collect = { Get-SmbMultichannelConstraint -ErrorAction Stop } }
                @{ Id = 'Get-SmbBandwidthLimit'; RelativePath = 'Smb\Get-SmbBandwidthLimit.json'; Collect = { Get-SmbBandwidthLimit -ErrorAction Stop } }
            )
        }
        @{
            Id = 'NetworkATC'
            TimeoutSeconds = 600
            Collectors = @(
                @{ Id = 'Get-NetIntent'; RelativePath = 'NetworkATC\Get-NetIntent.json'; Collect = { Get-NetIntent -ErrorAction Stop } }
                @{ Id = 'Get-NetIntentStatus'; RelativePath = 'NetworkATC\Get-NetIntentStatus.json'; Collect = { Get-NetIntentStatus -ErrorAction Stop | Where-Object { $null -ne $_ -and $_ -isnot [string] } } }
                @{ Id = 'Get-StorageNetworkIntent'; RelativePath = 'NetworkATC\Get-StorageNetworkIntent.json'; Collect = { Get-StorageNetworkIntent -ErrorAction Stop } }
                @{ Id = 'Get-NetIntentAllGoalStates'; RelativePath = 'NetworkATC\Get-NetIntentAllGoalStates.json'; Collect = { Get-NetIntentAllGoalStates -ErrorAction Stop } }
                @{ Id = 'Get-NetIntent-Cluster'; TestAvailable = { try { $null = Get-Cluster -ErrorAction Stop; $true } catch { $false } }; ExpectedUnavailableFailure = 'Failed to open local cluster'; RelativePath = 'NetworkATC\Get-NetIntent-Cluster.json'; Collect = { Get-NetIntent -ClusterName (Get-Cluster -ErrorAction Stop).Name -ErrorAction Stop } }
                @{ Id = 'Get-NetIntentStatus-Cluster'; TestAvailable = { try { $null = Get-Cluster -ErrorAction Stop; $true } catch { $false } }; ExpectedUnavailableFailure = 'Failed to open local cluster'; RelativePath = 'NetworkATC\Get-NetIntentStatus-Cluster.json'; Collect = { Get-NetIntentStatus -ClusterName (Get-Cluster -ErrorAction Stop).Name -ErrorAction Stop | Where-Object { $null -ne $_ -and $_ -isnot [string] } } }
                @{ Id = 'Get-NetIntentAllGoalStates-Cluster'; TestAvailable = { try { $null = Get-Cluster -ErrorAction Stop; $true } catch { $false } }; ExpectedUnavailableFailure = 'Failed to open local cluster'; RelativePath = 'NetworkATC\Get-NetIntentAllGoalStates-Cluster.json'; Collect = { Get-NetIntentAllGoalStates -ClusterName (Get-Cluster -ErrorAction Stop).Name -ErrorAction Stop } }
                @{ Id = 'Get-WinEvent-Networking-NetworkAtc-Operational'; Kind = 'Event'; LogName = 'Microsoft-Windows-Networking-NetworkAtc/Operational'; MaximumBytes = 10MB; RelativePath = 'NetworkATC\Get-WinEvent-Networking-NetworkAtc-Operational.json' }
                @{ Id = 'Get-WinEvent-Networking-NetworkAtc-Admin'; Kind = 'Event'; LogName = 'Microsoft-Windows-Networking-NetworkAtc/Admin'; MaximumBytes = 10MB; RelativePath = 'NetworkATC\Get-WinEvent-Networking-NetworkAtc-Admin.json' }
            )
        }
        @{
            Id = 'Proxy'
            TimeoutSeconds = 600
            Collectors = @(
                @{ Id = 'netsh-winhttp-show-proxy'; Kind = 'Text'; RelativePath = 'Proxy\netsh-winhttp-show-proxy.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName netsh.exe -ArgumentList 'winhttp', 'show', 'proxy' } }
                @{ Id = 'netsh-winhttp-show-advproxy'; Kind = 'Text'; RelativePath = 'Proxy\netsh-winhttp-show-advproxy.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName netsh.exe -ArgumentList 'winhttp', 'show', 'advproxy' } }
                @{ Id = 'netsh-winhttp-dump'; Kind = 'Text'; RelativePath = 'Proxy\netsh-winhttp-dump.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName netsh.exe -ArgumentList 'winhttp', 'dump' } }
            )
        }
        @{
            Id = 'Firewall'
            TimeoutSeconds = 600
            Collectors = @(
                @{ Id = 'Get-NetFirewallProfile'; RelativePath = 'Firewall\Get-NetFirewallProfile.json'; Collect = { Get-NetFirewallProfile -ErrorAction Stop } }
                @{ Id = 'netsh-advfirewall-show-allprofiles'; Kind = 'Text'; RelativePath = 'Firewall\netsh-advfirewall-show-allprofiles.txt'; Collect = { Invoke-StructuredDiagnosticNativeCommand -CommandName netsh.exe -ArgumentList 'advfirewall', 'show', 'allprofiles' } }
                @{ Id = 'Get-NetFirewallRule'; RelativePath = 'Firewall\Get-NetFirewallRule.json'; Collect = { Get-NetFirewallRule -ErrorAction Stop } }
                @{ Id = 'Get-NetFirewallAddressFilter'; RelativePath = 'Firewall\Get-NetFirewallAddressFilter.json'; Collect = { Get-NetFirewallAddressFilter -ErrorAction Stop } }
                @{ Id = 'Get-NetFirewallPortFilter'; RelativePath = 'Firewall\Get-NetFirewallPortFilter.json'; Collect = { Get-NetFirewallPortFilter -ErrorAction Stop } }
                @{ Id = 'Get-NetFirewallApplicationFilter'; RelativePath = 'Firewall\Get-NetFirewallApplicationFilter.json'; Collect = { Get-NetFirewallApplicationFilter -ErrorAction Stop } }
                @{ Id = 'Get-NetFirewallServiceFilter'; RelativePath = 'Firewall\Get-NetFirewallServiceFilter.json'; Collect = { Get-NetFirewallServiceFilter -ErrorAction Stop } }
                @{ Id = 'Get-NetFirewallInterfaceFilter'; RelativePath = 'Firewall\Get-NetFirewallInterfaceFilter.json'; Collect = { Get-NetFirewallInterfaceFilter -ErrorAction Stop } }
                @{ Id = 'Get-NetFirewallInterfaceTypeFilter'; RelativePath = 'Firewall\Get-NetFirewallInterfaceTypeFilter.json'; Collect = { Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop } }
                @{ Id = 'Get-NetFirewallSecurityFilter'; RelativePath = 'Firewall\Get-NetFirewallSecurityFilter.json'; Collect = { Get-NetFirewallSecurityFilter -ErrorAction Stop } }
            )
        }
    )
}

# =================================
#     Collector Helper Functions
# =================================

function Test-StructuredDiagnosticClusterAvailable {
    [CmdletBinding()]
    [OutputType([bool])]
    param ()

    if (-not (Get-Command -Name Get-Cluster -ErrorAction Ignore)) {
        return $false
    }
    try {
        $null = Get-Cluster -ErrorAction Stop
        return $true
    }
    catch {
        $_ | Trace-Exception
        Trace-Output -Level Warning -Message 'Local cluster data is unavailable; skipping cluster collectors.'
        return $false
    }
}

# Invokes a native command such as ipconfig or netsh and captures its output and exit code.
function Invoke-StructuredDiagnosticNativeCommand {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$CommandName,

        [Parameter()]
        [string[]]$ArgumentList = @()
    )

    $output = @(& $CommandName @ArgumentList 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        $message = 'Command {0} exited with code {1}.' -f $CommandName, $exitCode
        if ($output.Count -gt 0) {
            $message = '{0} Output: {1}' -f $message, ($output -join [Environment]::NewLine)
        }
        throw $message
    }
    $output
}

# Copies the newest portion of a file up to a size limit and atomically publishes the result.
function Copy-StructuredDiagnosticBoundedFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,

        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, [long]::MaxValue)]
        [long]$MaximumBytes
    )

    $source = Get-Item -LiteralPath $SourcePath -ErrorAction Stop
    $destinationDirectory = Split-Path -Path $DestinationPath -Parent
    $null = New-Item -Path $destinationDirectory -ItemType Directory -Force -ErrorAction Stop
    $temporaryPath = '{0}.{1}.tmp' -f $DestinationPath, [guid]::NewGuid().ToString('N')
    $sourceStream = $null
    $destinationStream = $null
    try {
        $sourceStream = [System.IO.File]::Open($source.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $destinationStream = [System.IO.File]::Create($temporaryPath)
        $originalBytes = $sourceStream.Length
        $copiedBytes = [Math]::Min($originalBytes, $MaximumBytes)
        # Preserve the most recent diagnostics when the source exceeds the collection limit.
        if ($originalBytes -gt $copiedBytes) {
            $null = $sourceStream.Seek(-$copiedBytes, [System.IO.SeekOrigin]::End)
        }
        $buffer = New-Object byte[] 65536
        $remaining = $copiedBytes
        while ($remaining -gt 0) {
            $read = $sourceStream.Read($buffer, 0, [int][Math]::Min($remaining, $buffer.Length))
            if ($read -eq 0) {
                throw 'The setup log changed before its bounded snapshot was copied.'
            }
            $destinationStream.Write($buffer, 0, $read)
            $remaining -= $read
        }
        $destinationStream.Dispose()
        $destinationStream = $null
        Move-Item -LiteralPath $temporaryPath -Destination $DestinationPath -Force -ErrorAction Stop
        [PSCustomObject]@{
            RelativePath = $DestinationPath
            Status = 'Success'
            OriginalBytes = $originalBytes
            CopiedBytes = $copiedBytes
            Truncated = $originalBytes -gt $copiedBytes
            FailureMessage = $null
        }
    }
    finally {
        if ($sourceStream) { $sourceStream.Dispose() }
        if ($destinationStream) { $destinationStream.Dispose() }
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
}

# Collects bounded copies of Windows network setup logs and reports each artifact's status.
function Copy-StructuredDiagnosticSetupLogs {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$OutputRoot
    )

    $maximumBytes = 5MB
    $sources = @(
        @{ SourcePath = Join-Path $env:windir 'INF\setupapi.dev.log'; FileName = 'setupapi.dev.txt' }
        @{ SourcePath = Join-Path $env:windir 'debug\NetSetup.log'; FileName = 'NetSetup.txt' }
    )
    foreach ($source in $sources) {
        if (-not (Test-Path -LiteralPath $source.SourcePath -PathType Leaf)) {
            [PSCustomObject]@{
                RelativePath = Join-Path 'Host\SetupLogs' $source.FileName
                Status = 'Unavailable'
                OriginalBytes = 0
                CopiedBytes = 0
                Truncated = $false
                FailureMessage = 'Source file is unavailable.'
            }
            continue
        }
        try {
            $destinationPath = Join-Path $OutputRoot (Join-Path 'Host\SetupLogs' $source.FileName)
            $artifact = Copy-StructuredDiagnosticBoundedFile -SourcePath $source.SourcePath -DestinationPath $destinationPath -MaximumBytes $maximumBytes
            $artifact.RelativePath = Join-Path 'Host\SetupLogs' $source.FileName
            $artifact
        }
        catch {
            $_ | Trace-Exception
            $_ | Write-Error -ErrorAction Continue
            [PSCustomObject]@{
                RelativePath = Join-Path 'Host\SetupLogs' $source.FileName
                Status = 'Failed'
                OriginalBytes = 0
                CopiedBytes = 0
                Truncated = $false
                FailureMessage = $_.Exception.Message
            }
        }
    }
}

# Maps a requested date range to the time-frame names accepted by performance collectors.
function Get-StructuredDiagnosticPerformanceTimeFrame {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [DateTime]$FromDate,

        [Parameter(Mandatory = $true)]
        [DateTime]$ToDate
    )

    if ($FromDate -gt $ToDate) {
        throw 'FromDate must be earlier than or equal to ToDate.'
    }

    $duration = $ToDate - $FromDate
    if ($duration -le [TimeSpan]::FromHours(1)) { return 'LastHour' }
    if ($duration -le [TimeSpan]::FromDays(1)) { return 'LastDay' }
    if ($duration -le [TimeSpan]::FromDays(7)) { return 'LastWeek' }
    if ($duration -le [TimeSpan]::FromDays(30)) { return 'LastMonth' }
    return 'LastYear'
}

# Exports parent, RDMA, and RSC adapter statistics into separate correlated artifacts.
function Export-StructuredDiagnosticNetAdapterStatistics {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$OutputRoot,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Json', 'Ndjson')]
        [string]$Format
    )

    $artifacts = @(
        @{ Name = 'Parent'; RelativePath = 'NetAdapter\Get-NetAdapterStatistics.json' }
        @{ Name = 'Rdma'; RelativePath = 'NetAdapter\Get-NetAdapterStatistics-Rdma.json' }
        @{ Name = 'Rsc'; RelativePath = 'NetAdapter\Get-NetAdapterStatistics-Rsc.json' }
    )
    $writers = @{}
    try {
        foreach ($artifact in $artifacts) {
            $writers[$artifact.Name] = Open-StructuredDiagnosticArtifactWriter -Path (Join-Path $OutputRoot $artifact.RelativePath) -Format $Format
        }

        $adaptersByName = @{}
        Get-NetAdapter -IncludeHidden -ErrorAction Stop | ForEach-Object {
            $adaptersByName[$_.Name] = $_
        }

        Get-NetAdapterStatistics -IncludeHidden -ErrorAction Stop | ForEach-Object {
            $statistics = $_
            $interfaceGuid = $adaptersByName[$statistics.Name].InterfaceGuid
            $parent = $statistics | Select-Object -Property * -ExcludeProperty RdmaStatistics, RscStatistics
            Write-StructuredDiagnosticArtifactRecord -Writer $writers.Parent -Record $parent
            # Add parent identity fields so detached nested statistics remain attributable to an adapter.
            @($statistics.RdmaStatistics) | Where-Object { $null -ne $_ } | ForEach-Object {
                $rdmaStatistics = $_ | Select-Object -Property *
                $rdmaStatistics | Add-Member -NotePropertyName Name -NotePropertyValue $statistics.Name -Force
                $rdmaStatistics | Add-Member -NotePropertyName InterfaceGuid -NotePropertyValue $interfaceGuid -Force
                Write-StructuredDiagnosticArtifactRecord -Writer $writers.Rdma -Record $rdmaStatistics
            }
            @($statistics.RscStatistics) | Where-Object { $null -ne $_ } | ForEach-Object {
                $rscStatistics = $_ | Select-Object -Property *
                $rscStatistics | Add-Member -NotePropertyName Name -NotePropertyValue $statistics.Name -Force
                $rscStatistics | Add-Member -NotePropertyName InterfaceGuid -NotePropertyValue $interfaceGuid -Force
                Write-StructuredDiagnosticArtifactRecord -Writer $writers.Rsc -Record $rscStatistics
            }
        }

        foreach ($artifact in $artifacts) {
            $writer = $writers[$artifact.Name]
            Close-StructuredDiagnosticArtifactWriter -Writer $writer
            [PSCustomObject]@{
                RelativePath = $artifact.RelativePath
                Status = 'Success'
                RecordCount = $writer.RecordCount
                FailureMessage = $null
            }
        }
    }
    finally {
        foreach ($writer in $writers.Values) {
            $writer.Stream.Dispose()
            if (Test-Path -LiteralPath $writer.TemporaryPath) {
                Remove-Item -LiteralPath $writer.TemporaryPath -Force
            }
        }
    }
}
