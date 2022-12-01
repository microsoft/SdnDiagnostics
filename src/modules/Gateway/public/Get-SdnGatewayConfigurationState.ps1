# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnGatewayConfigurationState {
    <#
    .SYNOPSIS
        Outputs a set of configuration state files for the gateway role.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .EXAMPLE
        PS> Get-SdnGatewayConfigurationState -OutputDirectory "C:\Temp\CSS_SDN"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    $ProgressPreference = 'SilentlyContinue'

    try {
        $config = Get-SdnRoleConfiguration -Role:Gateway
        [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath "ConfigState"
        [System.IO.FileInfo]$regDir = Join-Path -Path $OutputDirectory.FullName -ChildPath "Registry"

        "Collect configuration state details for role {0}" -f $config.Name | Trace-Output

        if (-NOT (Initialize-DataCollection -Role:Gateway -FilePath $OutputDirectory.FullName -MinimumMB 100)) {
            throw New-Object System.Exception("Unable to initialize environment for data collection")
        }

        # dump out the regkey properties
        Export-RegistryKeyConfigDetails -Path $config.properties.regKeyPaths -OutputDirectory $regDir.FullName

        # dump out the role configuration state properties
        "Getting RRAS VPN configuration details" | Trace-Output -Level:Verbose
        Get-VpnServerConfiguration | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VpnServerConfiguration' -FileType txt -Format Table
        Get-VpnS2SInterface | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VpnS2SInterface' -FileType txt -Format List
        Get-RemoteaccessRoutingDomain | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-RemoteaccessRoutingDomain' -FileType txt -Format List

        foreach ($routingDomain in Get-RemoteAccessRoutingDomain) {
            "Getting properties for routing domain {0}" -f $routingDomain.RoutingDomain | Trace-Output -Level:Verbose
            $routingDomainPath = New-Item -Path (Join-Path -Path $OutputDirectory.FullName -ChildPath $routingDomain.RoutingDomainID) -ItemType Directory -Force
            Get-BgpRouter -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -Name 'Get-BgpRouter' -FileType txt -Format List
            Get-BgpPeer -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -Name 'Get-BgpPeer' -FileType txt -Format List
            Get-BgprouteInformation -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -Name 'Get-BgprouteInformation' -FileType txt -Format List
            Get-BgpCustomRoute -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -Name 'Get-BgpCustomRoute' -FileType txt -Format List
            Get-BgpStatistics -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -Name 'Get-BgpStatistics' -FileType txt -Format List
            Get-BgpRoutingPolicy -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -Name 'Get-BgpRoutingPolicy' -FileType txt -Format List
            Get-BgpRouteFlapDampening -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -Name 'Get-BgpRouteFlapDampening' -FileType txt -Format List
            Get-BgpRouteAggregate -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -Name 'Get-BgpRouteAggregate' -FileType txt -Format List
        }

        # for ipsec fast path, there is a new service w/ new cmdlets to get the tunnels and routing domains
        if ((Get-Service -Name GatewayService).Status -ieq 'Running') {
            "GatewayService is enabled. Getting GatewayService configuration details" | Trace-Output -Level:Verbose
            $gatewayServicePath = New-Item -Path (Join-Path -Path $OutputDirectory.FullName -ChildPath 'GatewayService') -ItemType Directory -Force
            Get-Service -Name GatewayService | Export-ObjectToFile -FilePath $gatewayServicePath.FullName -Prefix 'GatewayService' -Name 'Get-Service' -FileType txt -Format List
            Get-GatewayConfiguration | Export-ObjectToFile -FilePath $gatewayServicePath.FullName -Name 'Get-GatewayConfiguration' -FileType txt -Format List
            Get-GatewayRoutingDomain | Export-ObjectToFile -FilePath $gatewayServicePath.FullName -Name 'Get-GatewayRoutingDomain' -FileType txt -Format List
            Get-GatewayTunnel | Export-ObjectToFile -FilePath $gatewayServicePath.FullName -Name 'Get-GatewayTunnel' -FileType txt -Format List
            Get-GatewayTunnelStatistics | Export-ObjectToFile -FilePath $gatewayServicePath.FullName -Name 'Get-GatewayTunnelStatistics' -FileType txt -Format List

            foreach ($routingDomain in  Get-GatewayRoutingDomain) {
                "Getting properties for routing domain {0}" -f $routingDomain.RoutingDomain | Trace-Output -Level:Verbose
                $routingDomainPath = New-Item -Path (Join-Path -Path $gatewayServicePath.FullName -ChildPath $routingDomain.RoutingDomain) -ItemType Directory -Force
                Get-BgpRouter -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -Name 'Get-BgpRouter' -FileType txt -Format List
                Get-BgpPeer -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -Name 'Get-BgpPeer' -FileType txt -Format List
                Get-BgpRouteInformation -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -Name 'Get-BgpRouteInformation' -FileType txt -Format List
                Get-BgpCustomRoute -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -Name 'Get-BgpCustomRoute' -FileType txt -Format List
            }
        }

        Get-GeneralConfigurationState -OutputDirectory $OutputDirectory.FullName
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }

    $ProgressPreference = 'Continue'
}
