function Get-SdnSlbMuxConfigurationState {
    <#
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    $ProgressPreference = 'SilentlyContinue'

    try {
        $config = Get-SdnRoleConfiguration -Role:SoftwareLoadBalancer

        # ensure that the appropriate windows feature is installed and ensure module is imported
        $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
        if(!$confirmFeatures){
            throw New-Object System.Exception("Required feature is missing")
        }

        $confirmModules = Confirm-RequiredModulesLoaded -Name $config.requiredModules
        if(!$confirmModules){
            throw New-Object System.Exception("Required module is not loaded")
        }

        # create the OutputDirectory if does not already exist
        if(!(Test-Path -Path $OutputDirectory.FullName -PathType Container)){
            $null = New-Item -Path $OutputDirectory.FullName -ItemType Directory -Force
        }

        # dump out the regkey properties
        Export-RegistryKeyConfigDetails -Path $config.properties.regKeyPaths -OutputDirectory (Join-Path -Path $OutputDirectory.FullName -ChildPath "Registry")

        # output slb configuration and states
        "Getting MUX Driver Control configuration settings" | Trace-Output -Level:Verbose
        MuxDriverControlConsole.exe /GetMuxState | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'GetMuxState' -FileType txt
        MuxDriverControlConsole.exe /GetMuxConfig | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'GetMuxConfig' -FileType txt
        MuxDriverControlConsole.exe /GetMuxStats | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'GetMuxStats' -FileType txt
        MuxDriverControlConsole.exe /GetMuxVipList | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'GetMuxVipList' -FileType txt
        MuxDriverControlConsole.exe /GetMuxDripList | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'GetMuxDripList' -FileType txt
        MuxDriverControlConsole.exe /GetStatelessVip | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'GetStatelessVip' -FileType txt
        MuxDriverControlConsole.exe /GetStatefulVip | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'GetStatefulVip' -FileType txt 

        Get-GeneralConfigurationState -OutputDirectory $OutputDirectory.FullName
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }

    $ProgressPreference = 'Continue'
}

function Get-SdnServerConfigurationState {
    <#
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    $ProgressPreference = 'SilentlyContinue'

    try {
        $config = Get-SdnRoleConfiguration -Role:Server

        # ensure that the appropriate windows feature is installed and ensure module is imported
        $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
        if(!$confirmFeatures){
            throw New-Object System.Exception("Required feature is missing")
        }

        $confirmModules = Confirm-RequiredModulesLoaded -Name $config.requiredModules
        if(!$confirmModules){
            throw New-Object System.Exception("Required module is not loaded")
        }

        # create the OutputDirectory if does not already exist
        if(!(Test-Path -Path $OutputDirectory.FullName -PathType Container)){
            $null = New-Item -Path $OutputDirectory.FullName -ItemType Directory -Force
        }

        # dump out the regkey properties
        Export-RegistryKeyConfigDetails -Path $config.properties.regKeyPaths -OutputDirectory (Join-Path -Path $OutputDirectory.FullName -ChildPath "Registry")

        # Gather VFP port configuration details
        "Gathering VFP port details" | Trace-Output -Level:Verbose
        foreach ($vm in (Get-WmiObject -na root\virtualization\v2 msvm_computersystem)){
            foreach ($vma in $vm.GetRelated("Msvm_SyntheticEthernetPort")){
                foreach ($port in $vma.GetRelated("Msvm_SyntheticEthernetPortSettingData").GetRelated("Msvm_EthernetPortAllocationSettingData").GetRelated("Msvm_EthernetSwitchPort")){
                    
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

        # Gather OVSDB databases
        "Gathering ovsdb database output" | Trace-Output -Level:Verbose
        ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_vtep | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'ovsdb_vtep' -FileType txt
        ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_firewall | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'ovsdb_firewall' -FileType txt
        ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_service_insertion | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'ovsdb_serviceinsertion' -FileType txt
        ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_vtep -f json -pretty| Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'ovsdb_vtep' -FileType json
        ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_firewall -f json -pretty | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'ovsdb_firewall' -FileType json
        ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_service_insertion -f json -pretty | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'ovsdb_serviceinsertion' -FileType json

        # Gather Hyper-V network details
        "Gathering hyper-v configuration details" | Trace-Output -Level:Verbose
        Get-PACAMapping | Sort-Object PSComputerName | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-PACAMapping' -FileType txt -Format Table
        Get-ProviderAddress | Sort-Object PSComputerName | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-ProviderAddress' -FileType txt -Format Table
        Get-CustomerRoute | Sort-Object PSComputerName | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-CustomerRoute' -FileType txt -Format Table
        Get-NetAdapterVPort | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetAdapterVPort' -FileType txt -Format Table
        Get-NetAdapterVmqQueue | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetAdapterVmqQueue' -FileType txt -Format Table
        Get-VMSwitch | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMSwitch' -FileType txt -Format List 
        Get-VMSwitchTeam | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMSwitchTeam' -FileType txt -Format List
        Get-VMNetAdapterPortProfile -AllVMs | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMNetAdapterPortProfile' -FileType txt -Format Table
        Get-VMNetworkAdapterIsolation | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMNetworkAdapterIsolation' -FileType txt -Format Table
        Get-VMNetworkAdapterRoutingDomainMapping | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VMNetworkAdapterRoutingDomainMapping' -FileType txt -Format Table

        Get-GeneralConfigurationState -OutputDirectory $OutputDirectory.FullName
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }

    $ProgressPreference = 'Continue'
}

function Get-SdnNetControllerConfigurationState {
    <#
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    $ProgressPreference = 'SilentlyContinue'
    
    try {
        $config = Get-SdnRoleConfiguration -Role:NetworkController

        # ensure that the appropriate windows feature is installed and ensure module is imported
        $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
        if(!$confirmFeatures){
            throw New-Object System.Exception("Required feature is missing")
        }

        $confirmModules = Confirm-RequiredModulesLoaded -Name $config.requiredModules
        if(!$confirmModules){
            throw New-Object System.Exception("Required module is not loaded")
        }

        # create the OutputDirectory if does not already exist
        if(!(Test-Path -Path $OutputDirectory.FullName -PathType Container)){
            $null = New-Item -Path $OutputDirectory.FullName -ItemType Directory -Force
        }

        # dump out the regkey properties
        Export-RegistryKeyConfigDetails -Path $config.properties.regKeyPaths -OutputDirectory (Join-Path -Path $OutputDirectory.FullName -ChildPath "Registry")

        # enumerate dll binary version for NC application
        "Getting"
        $ncAppDirectories = Get-ChildItem -Path "C:\Windows\NetworkController" -Directory
        $outputDir = New-Item -Path (Join-Path -Path $OutputDirectory.FullName -ChildPath "NCApplication") -ItemType Directory -Force
        foreach($directory in $ncAppDirectories){
            [System.String]$fileName = "FileInfo_{0}" -f $directory.BaseName
            Get-Item -Path "$($directory.FullName)\*" -Include *.dll,*.exe | Export-ObjectToFile -FilePath $outputDir.FullName -Name $fileName -FileType txt -Format List
        }

        Get-GeneralConfigurationState -OutputDirectory $OutputDirectory.FullName
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }

    $ProgressPreference = 'Continue'
}

function Get-SdnGatewayConfigurationState {
    <#
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    $ProgressPreference = 'SilentlyContinue'

    try {
        $config = Get-SdnRoleConfiguration -Role:Gateway

        # ensure that the appropriate windows feature is installed and ensure module is imported
        $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
        if(!$confirmFeatures){
            throw New-Object System.Exception("Required feature is missing")
        }

        $confirmModules = Confirm-RequiredModulesLoaded -Name $config.requiredModules
        if(!$confirmModules){
            throw New-Object System.Exception("Required module is not loaded")
        }

        # create the OutputDirectory if does not already exist
        if(!(Test-Path -Path $OutputDirectory.FullName -PathType Container)){
            $null = New-Item -Path $OutputDirectory.FullName -ItemType Directory -Force
        }

        # dump out the regkey properties
        Export-RegistryKeyConfigDetails -Path $config.properties.regKeyPaths -OutputDirectory (Join-Path -Path $OutputDirectory.FullName -ChildPath "Registry")

        # dump out the role configuration state properties
        "Getting RRAS VPN configuration details" | Trace-Output -Level:Verbose
        Get-VpnServerConfiguration | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VpnServerConfiguration' -FileType txt -Format Table
        Get-VpnS2SInterface | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VpnS2SInterface' -FileType txt -Format List
        Get-RemoteaccessRoutingDomain | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-RemoteaccessRoutingDomain' -FileType txt -Format List

        foreach ($routingDomain in Get-RemoteAccessRoutingDomain){
            "Getting properties for routing domain {0}" -f $routingDomain.RoutingDomain | Trace-Output -Level:Verbose
            $routingDomainPath = New-Item -Path (Join-Path -Path $OutputDirectory.FullName -ChildPath $routingDomain.RoutingDomainID) -ItemType Directory -Force
            Get-BgpRouter -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -Name 'Get-BgpRouter' -FileType txt -Format List
            Get-BgpRouter -RoutingDomain $routingDomain.RoutingDomain | Get-BgpPeer | Export-ObjectToFile -FilePath $routingDomainPath.FullName -Name 'Get-BgpPeer' -FileType txt -Format List
            Get-BgprouteInformation -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -Name 'Get-BgprouteInformation' -FileType txt -Format List
            Get-BgpCustomRoute -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -Name 'Get-BgpCustomRoute' -FileType txt -Format List
        }

        # for ipsec fast path, there is a new service w/ new cmdlets to get the tunnels and routing domains
        if((Get-Service -Name GatewayService).Status -ieq 'Running'){
            "GatewayService is enabled. Getting GatewayService configuration details" | Trace-Output -Level:Verbose
            $gatewayServicePath = New-Item -Path (Join-Path -Path $OutputDirectory.FullName -ChildPath 'GatewayService') -ItemType Directory -Force
            Get-Service -Name GatewayService | Export-ObjectToFile -FilePath $gatewayServicePath.FullName -Prefix 'GatewayService' -Name 'Get-Service' -FileType txt -Format List
            Get-GatewayConfiguration | Export-ObjectToFile -FilePath $gatewayServicePath.FullName -Name 'Get-GatewayConfiguration' -FileType txt -Format List
            Get-GatewayRoutingDomain | Export-ObjectToFile -FilePath $gatewayServicePath.FullName -Name 'Get-GatewayRoutingDomain' -FileType txt -Format List
            Get-GatewayTunnel | Export-ObjectToFile -FilePath $gatewayServicePath.FullName -Name 'Get-GatewayTunnel' -FileType txt -Format List
            Get-GatewayTunnelStatistics | Export-ObjectToFile -FilePath $gatewayServicePath.FullName -Name 'Get-GatewayTunnelStatistics' -FileType txt -Format List

            foreach($routingDomain in  Get-GatewayRoutingDomain){
                "Getting properties for routing domain {0}" -f $routingDomain.RoutingDomain | Trace-Output -Level:Verbose
                $routingDomainPath = New-Item -Path (Join-Path -Path $gatewayServicePath.FullName -ChildPath $routingDomain.RoutingDomain) -ItemType Directory -Force
                Get-BgpRouter -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -Name 'Get-BgpRouter' -FileType txt -Format List
                Get-BgpRouter -RoutingDomain $routingDomain.RoutingDomain | Get-BgpPeer | Export-ObjectToFile -FilePath $routingDomainPath.FullName -Name 'Get-BgpPeer' -FileType txt -Format List
                Get-BgpRouteInformation -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -Name 'Get-BgpRouteInformation' -FileType txt -Format List
                Get-BgpCustomRoute -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -Name 'Get-BgpCustomRoute' -FileType txt -Format List
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }

    $ProgressPreference = 'Continue'
}

function Get-SdnApiResource {
    <#
    .SYNOPSIS
        Returns a list of gateways from network controller
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        [System.IO.FileInfo]$outputDir = Join-Path -Path $OutputDirectory.FullName -ChildPath 'SdnApiResources'
        if(!(Test-Path -Path $outputDir.FullName -PathType Container)){
            $null = New-Item -Path $outputDir.FullName -ItemType Directory -Force
        }

        foreach($resource in $SdnDiagnostics.Settings.apiResources){
            try {
                Get-SdnResource -NcUri $NcUri.AbsoluteUri -ResourceRef $resource -Credential $Credential | Export-ObjectToFile -FilePath $outputDir.FullName -Name $resource.Replace('/','_') -FileType json
            }
            catch {
                $_.Exception | Trace-Output -Level:Warning
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnNetworkControllerState {
    <#
    .SYNOPSIS
        Gathers the IMOS dump files from each of the Network Controllers
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER ComputerName
        The computer name(s) of the Network Controllers that the IMOS dump files need to be collected from
    .PARAMETER OutputDirectory
        Directory location to save results. By default it will create a new sub-folder called NetworkControllerState that the files will be copied to
    .PARAMETER ExecutionTimeout
        Specify the execution timeout (seconds) on how long you want to wait for operation to complete before cancelling operation
        Default: 300
    .EXAMPLE 
        Get-SdnNcImosDumpFiles -NcUri "https://nc.contoso.com" -ComputerName $NetworkControllers -OutputDirectory "C:\Temp\CSS_SDN"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $true)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [int]$ExecutionTimeOut = 300
    )
    try {
        $config = Get-SdnRoleConfiguration -Role:NetworkController
        [System.IO.FileInfo]$netControllerStatePath = $config.properties.netControllerStatePath
        [System.IO.FileInfo]$outputDir = Join-Path -Path $OutputDirectory.FullName -ChildPath 'NetworkControllerState'

        if(!(Test-Path -Path $outputDir.FullName -PathType Container)){
            $null = New-Item -Path $outputDir.FullName -ItemType Directory -Force
        }

        $scriptBlock = {
            try {
                if(Test-Path -Path $using:netControllerStatePath.FullName -PathType Container){
                    Get-Item -Path $using:netControllerStatePath.FullName | Remove-Item -Recurse -Confirm:$false -Force -ErrorAction SilentlyContinue
                }
    
                $null = New-Item -Path $using:netControllerStatePath.FullName -ItemType Container -Force
            }
            catch {
                $_ | Write-Error
            }
        }

        # invoke scriptblock to clean up any stale NetworkControllerState files
        Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential

        # invoke the call to generate the files
        # once the operation completes and returns true, then enumerate through the ComputerNames defined to collect the files
        $result = Invoke-SdnNetworkControllerStateDump -NcUri $NcUri.AbsoluteUri -Credential $NcRestCredential -ExecutionTimeOut $ExecutionTimeOut
        if($result){
            foreach($obj in $ComputerName){
                Copy-FileFromPSRemoteSession -Path "$($config.properties.netControllerStatePath)\*" -ComputerName $obj -Destination $outputDir.FullName
            }
        }        
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Invoke-SdnGetNetView {
    <#
    .SYNOPSIS
        Invokes Get-Netview function on the specified ComputerNames.
    .PARAMETER ComputerName
        The computer name(s) to perform operation against
    .PARAMETER OutputDirectory
        Optional path to the directory where the output should be saved. Can be either a relative or an absolute path.
        If unspecified, the current user's Desktop will be used by default.
    .PARAMETER BackgroundThreads
        Maximum number of background tasks, from 0 - 16. Defaults to 5.
    .PARAMETER SkipAdminCheck
        If present, skip the check for admin privileges before execution. Note that without admin privileges, the scope and
        usefulness of the collected data is limited.
    .PARAMETER SkipLogs
        If present, skip the EVT and WER logs gather phases.
    .PARAMETER SkipNetshTrace
        If present, skip the Netsh Trace data gather phases.
    .PARAMETER SkipCounters
        If present, skip the Windows Performance Counters (WPM) data gather phases.
    .EXAMPLE
        PS > Invoke-SdnNetView -ComputerName (Get-SdnServer -NcUri $uri -ManagementAddressOnly)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [int]$BackgroundThreads = 5,

        [Parameter(Mandatory = $false)]
        [switch]$SkipAdminCheck,

        [Parameter(Mandatory = $false)]
        [switch]$SkipLogs,

        [Parameter(Mandatory = $false)]
        [switch]$SkipNetshTrace,

        [Parameter(Mandatory = $false)]
        [switch]$SkipCounters,

        [Parameter(Mandatory = $false)]
        [switch]$SkipVm
    )

    try {
        Copy-Item -Path "$PSScriptRoot\..\..\tools\GetNetView" -Destination "C:\Program Files\WindowsPowerShell\Modules" -Force -Recurse
        Import-Module -Name 'Get-NetView' -Force
        "Using Get-NetView version {0}" -f (Get-Module -Name 'Get-NetView' -ErrorAction SilentlyContinue).Version.ToString() | Trace-Output -Level:Verbose

        # validate the output directory exists, else create the appropriate path
        if(!(Test-Path -Path $OutputDirectory.FullName -PathType Container)){
            $null = New-Item -Path $OutputDirectory.FullName -ItemType Directory -Force
        }

        # execute Get-NetView with specified parameters and redirect all streams to null to prevent unnecessary noise on the screen
        Get-NetView -OutputDirectory $OutputDirectory.FullName `
            -BackgroundThreads $BackgroundThreads `
            -SkipAdminCheck:$SkipAdminCheck.IsPresent `
            -SkipLogs:$SkipLogs.IsPresent `
            -SkipNetshTrace:$SkipNetshTrace.IsPresent `
            -SkipCounters:$SkipCounters.IsPresent `
            -SkipVm:$SkipVm.IsPresent *> $null

        # remove the uncompressed files and folders to free up ~ 1.5GB of space
        $compressedArchive = Get-ChildItem -Path $OutputDirectory -Filter "*.zip"
        if($compressedArchive){
            Get-ChildItem -Path $OutputDirectory -Exclude *.zip | Remove-Item -Recurse -Confirm:$false
        }

        return $compressedArchive.FullName
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Start-SdnDataCollection {

    <#
        .SYNOPSIS
        Automated network diagnostics and data collection/tracing script.

        .PARAMETER DataCollectionType 
        Optional parameter that allows the user to define if they want to collect either Configuration, Logs or None. Default is Logs
            Configuration - Gathers basic configuration details related to SDN infrastructure
            Logs - Gathers diagnostics logs and event traces, in addition to configuration details

        .PARAMETER Scenario
        Required parameter that allows you to specify the datapath scenario you want to enable
            SLB - Adds the appropriate SLB nodes as part of the data collection 
            Gateway - Add the appropriate Gateway nodes as part of the data collection
            None - No scenario

        .PARAMETER EnableNetworkTraces
        Optional switch parameter that allows you to collect network traces as part of the data collection process

        .PARAMETER OutputDirectory

        .PARAMETER RemoteSharePath
        Optional parameter that allows you to output results to a remote network share

        .PARAMETER RemoteShareCredentials
        Optional parameter used in conjuction with RemoteSharePath that provides appropriate credentials to access the RemoteSharePath location

        .PARAMETER FromDate
        Optional parameter that allows you to control how many hours worth of logs to retrieve from the system for the roles identified. Default is 120 hours.
            (Get-Date).AddHours(-4)

        .PARAMETER MaxTraceSize
        Optional parameter that allows you to define maximum size allowed for network trace. Default is 2048 MB
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [System.IO.FileInfo]$OutputDirectory,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Configuration','Logs','None')]
        [System.String]$DataCollectionType = 'Logs',

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    "Starting SDN Data Collection" | Trace-Output
    if($null -eq $OutputDirectory){
        [System.IO.FileInfo]$OutputDirectory = (Get-WorkingDirectory)
    }

    [System.IO.FileInfo]$outputDir = (Join-Path -Path $OutputDirectory.FullName -ChildPath (Get-FormattedDateTimeUTC))
    "Results will be saved to {0}" -f $outputDir.FullName | Trace-Output

    "Generating output of the NC API resources" | Trace-Output
    Get-SdnApiResource -NcUri $NcUri.AbsoluteUri -OutputDirectory $outputDir.FullName -Credential $Credential
}