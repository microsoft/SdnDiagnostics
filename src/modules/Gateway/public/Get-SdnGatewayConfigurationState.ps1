# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
        if (!$confirmFeatures) {
            throw New-Object System.Exception("Required feature is missing")
        }

        $confirmModules = Confirm-RequiredModulesLoaded -Name $config.requiredModules
        if (!$confirmModules) {
            throw New-Object System.Exception("Required module is not loaded")
        }

        # create the OutputDirectory if does not already exist
        if (!(Test-Path -Path $OutputDirectory.FullName -PathType Container)) {
            $null = New-Item -Path $OutputDirectory.FullName -ItemType Directory -Force
        }

        # dump out the regkey properties
        Export-RegistryKeyConfigDetails -Path $config.properties.regKeyPaths -OutputDirectory (Join-Path -Path $OutputDirectory.FullName -ChildPath "Registry")

        # dump out the role configuration state properties
        "Getting RRAS VPN configuration details" | Trace-Output -Level:Verbose
        Get-VpnServerConfiguration | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VpnServerConfiguration' -FileType txt -Format Table
        Get-VpnS2SInterface | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-VpnS2SInterface' -FileType txt -Format List
        Get-RemoteaccessRoutingDomain | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-RemoteaccessRoutingDomain' -FileType txt -Format List

        foreach ($routingDomain in Get-RemoteAccessRoutingDomain) {
            "Getting properties for routing domain {0}" -f $routingDomain.RoutingDomain | Trace-Output -Level:Verbose
            $routingDomainPath = New-Item -Path (Join-Path -Path $OutputDirectory.FullName -ChildPath $routingDomain.RoutingDomainID) -ItemType Directory -Force
            Get-BgpRouter -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -Name 'Get-BgpRouter' -FileType txt -Format List
            Get-BgpRouter -RoutingDomain $routingDomain.RoutingDomain | Get-BgpPeer | Export-ObjectToFile -FilePath $routingDomainPath.FullName -Name 'Get-BgpPeer' -FileType txt -Format List
            Get-BgprouteInformation -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -Name 'Get-BgprouteInformation' -FileType txt -Format List
            Get-BgpCustomRoute -RoutingDomain $routingDomain.RoutingDomain | Export-ObjectToFile -FilePath $routingDomainPath.FullName -Name 'Get-BgpCustomRoute' -FileType txt -Format List
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
