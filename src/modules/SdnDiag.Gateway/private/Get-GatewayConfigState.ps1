function Get-GatewayConfigState {
    <#
    .SYNOPSIS
        Outputs a set of configuration state files for the gateway role.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .EXAMPLE
        PS> Get-GatewayConfigState -OutputDirectory "C:\Temp\CSS_SDN"
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
        $config = Get-SdnModuleConfiguration -Role 'Gateway'
        [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath "ConfigState"
        [System.IO.FileInfo]$regDir = Join-Path -Path $OutputDirectory.FullName -ChildPath "Registry"

        "Collect configuration state details for role {0}" -f $config.Name | Trace-Output

        if (-NOT (Initialize-DataCollection -Role 'Gateway' -FilePath $OutputDirectory.FullName -MinimumMB 100)) {
            "Unable to initialize environment for data collection" | Trace-Output -Level:Error
            return
        }

        Export-RegistryKeyConfigDetails -Path $config.properties.regKeyPaths -OutputDirectory $regDir.FullName
        Get-CommonConfigState -OutputDirectory $OutputDirectory.FullName

        # dump out the role configuration state properties
        "Getting RRAS VPN configuration details" | Trace-Output -Level:Verbose
        Get-VpnServerConfiguration | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType txt -Format Table
        Get-VpnS2SInterface | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType txt -Format List
        Get-RemoteaccessRoutingDomain | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType txt -Format List

        foreach ($routingDomain in Get-RemoteAccessRoutingDomain) {
            "Getting properties for routing domain {0}" -f $routingDomain.RoutingDomain | Trace-Output -Level:Verbose
            $routingDomainPath = New-Item -Path (Join-Path -Path $OutputDirectory.FullName -ChildPath $routingDomain.RoutingDomainID) -ItemType Directory -Force
            Get-BgpRouter -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -FileType txt -Format List
            Get-BgpPeer -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -FileType txt -Format List
            Get-BgprouteInformation -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -FileType txt -Format List
            Get-BgpCustomRoute -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -FileType txt -Format List
            Get-BgpStatistics -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -FileType txt -Format List
            Get-BgpRoutingPolicy -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -FileType txt -Format List
            Get-BgpRouteFlapDampening -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -FileType txt -Format List
            Get-BgpRouteAggregate -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -FileType txt -Format List
        }

        # for ipsec fast path, there is a new service w/ new cmdlets to get the tunnels and routing domains
        if ((Get-Service -Name 'GatewayService').Status -ieq 'Running') {
            "GatewayService is enabled. Getting GatewayService configuration details" | Trace-Output -Level:Verbose
            $gatewayServicePath = New-Item -Path (Join-Path -Path $OutputDirectory.FullName -ChildPath 'GatewayService') -ItemType Directory -Force
            Get-Service -Name 'GatewayService' | Export-ObjectToFile -FilePath $gatewayServicePath.FullName -Prefix 'GatewayService' -FileType txt -Format List
            Get-GatewayConfiguration | Export-ObjectToFile -FilePath $gatewayServicePath.FullName -FileType txt -Format List
            Get-GatewayRoutingDomain | Export-ObjectToFile -FilePath $gatewayServicePath.FullName -FileType txt -Format List
            Get-GatewayTunnel | Export-ObjectToFile -FilePath $gatewayServicePath.FullName -FileType txt -Format List
            Get-GatewayTunnelStatistics | Export-ObjectToFile -FilePath $gatewayServicePath.FullName -FileType txt -Format List

            foreach ($routingDomain in  Get-GatewayRoutingDomain) {
                "Getting properties for routing domain {0}" -f $routingDomain.RoutingDomain | Trace-Output -Level:Verbose
                $routingDomainPath = New-Item -Path (Join-Path -Path $gatewayServicePath.FullName -ChildPath $routingDomain.RoutingDomain) -ItemType Directory -Force
                Get-BgpRouter -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -FileType txt -Format List
                Get-BgpPeer -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -FileType txt -Format List
                Get-BgpRouteInformation -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -FileType txt -Format List
                Get-BgpCustomRoute -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -FileType txt -Format List
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
