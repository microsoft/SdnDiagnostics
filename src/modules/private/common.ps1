function Get-SdnRoleConfiguration {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnRoles]$Role
    )

    return (Get-Content -Path "$PSScriptRoot\..\..\config\role\$Role.json" | ConvertFrom-Json)
}

function Confirm-RequiredModulesLoaded {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String[]]$Name
    )

    try {

        if($null -eq $Name){
            return $true
        }
        else {
            foreach($obj in $Name){
                if(!(Get-Module -Name $obj)){
                    Import-Module -Name $obj -Force -ErrorAction Stop
                }
            }

            return $true
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
        return $false
    }
}

function Confirm-RequiredFeaturesInstalled {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String[]]$Name
    )

    try {

        if($null -eq $Name){
            return $true
        }
        else {
            foreach($obj in $Name){
                if(!(Get-WindowsFeature -Name $obj).Installed){
                    "Required feature {0} is not installed on {1}" -f $obj, $env:COMPUTERNAME | Trace-Output -Level:Error
                    return $false
                }
            }
    
            return $true
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
        return $false
    }
}

function Get-SdnApiEndpoint {
    <##>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $true, ParameterSetName = 'NoResourceRef')]
        [Uri]$NcUri,

        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $true, ParameterSetName = 'NoResourceRef')]
        [System.String]$ApiVersion,

        [Parameter(Mandatory = $true, ParameterSetName = 'NoResourceRef')]
        [System.String]$ServiceName,

        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceRef')]
        [System.String]$ResourceRef
    )

    try {
        $apiEndpoints = @{
            AccessControlLists = "accessControlLists"
            Credentials = "credentials"
            GatewayPools = "gatewayPools"
            Gateways = "gateways"
            iDNSServerConfig = "iDNSServer/configuration"
            LoadBalancerManagerConfig = "loadBalancerManager/config"
            LoadBalancerMuxes = "loadBalancerMuxes"
            LoadBalancers = "loadBalancers"
            LogicalNetworks = "logicalNetworks"
            MacPools = "macPools"
            NetworkControllerState = "diagnostics/networkControllerState"
            NetworkInterfaces = "networkInterfaces"
            PublicIPAddresses = "publicIPAddresses"
            Servers = "servers"
            SlbState = "diagnostics/slbState"
            RouteTables = "routeTables"
            VirtualGateways = "virtualGateways"
            VirtualNetworkManagerConfig = "virtualNetworkManager/configuration"
            VirtualNetworks = "virtualNetworks"
            VirtualServers = "virtualServers"
        }

        if($PSBoundParameters.ContainsKey('ResourceRef')){
            [System.String]$endpoint = "{0}/networking/{1}/{2}" -f $NcUri.AbsoluteUri.TrimEnd('/'), $ApiVersion, $ResourceRef.TrimStart('/')
        }
        else {
            [System.String]$endpoint = "{0}/networking/{1}/{2}" -f $NcUri.AbsoluteUri.TrimEnd('/'), $ApiVersion, $apiEndpoints[$ServiceName]
        }

        "Endpoint: {0}" -f $endpoint | Trace-Output -Level:Verbose
        return $endpoint
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}