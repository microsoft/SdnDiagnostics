function Set-SdnInternalDnsConfiguration {
    <#
    .SYNOPSIS
        Configures the Internal DNS (iDNS) service to provide default name resolution services for tenant workloads.
    .DESCRIPTION
        Automates the configuration of iDNS by configuring the appropriate NB API endpoint, setting credentials and configuring the appropriate registry keys on the hypervisor servers.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
    .PARAMETER ZoneName
        The zone within DNS that will be used to host the iDNS records.
    .PARAMETER DnsForwarderAddress
        The FQDN or IP Address of the AD-Integrated DNS servers that will be used to service DNS requests for tenant workloads.
    .PARAMETER ProxyIpAddress
        The fixed IP address configured on the guest OS network interface if tenant chooses to use iDNS service. If omitted, defaults to 168.63.129.16.
    .PARAMETER ProxyMacAddress
        When client ARPs for the DNS Server IP, the host agent will respond with this MAC address. This can be any random MAC, as long as it does not conflict. If omitted, defaults to aa-bb-cc-aa-bb-cc.
    .PARAMETER HostCredential
        Specifies a user account that has appropriate permissions to hypervisor hosts to configure registry paths and keys and restart services. If omitted, defaults to current user.
    .PARAMETER NcCredential
        Specifies a user account that has appropriate permissions to Network Controllers to confirm WinRM TrustedHosts (if applicable) and perform Service Fabric operations. If omitted, defaults to current user.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to access the northbound NC API interface. If omitted, defaults to current user.
    .PARAMETER DnsForwarderCredential
        Specifies a user account that has appropriate permissions to the DNS Forwarders. This credential will be leveraged by Network Controller to create the DNS Zone and manage records.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$NetworkController = $(HostName),

        [Parameter(Mandatory = $true)]
        [System.String]$ZoneName,

        [Parameter(Mandatory = $true)]
        [System.String[]]$DnsForwarderAddress,

        [Parameter(Mandatory = $false)]
        [System.String]$ProxyIpAddress = '168.63.129.16',

        [Parameter(Mandatory = $false)]
        [System.String]$ProxyMacAddress = 'aa-bb-cc-aa-bb-cc',

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$DnsForwarderCredential,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $HostCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    # ensure that the module is running as local administrator
    $elevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-NOT $elevated) {
        throw New-Object System.Exception("This function requires elevated permissions. Run PowerShell as an Administrator and import the module again.")
    }

    if (-NOT ($PSBoundParameters.ContainsKey('NetworkController'))) {
        $config = Get-SdnModuleConfiguration -Role 'NetworkController'
        $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
        if (-NOT ($confirmFeatures)) {
            "The current machine is not a NetworkController, run this on NetworkController or use -NetworkController parameter to specify one" | Trace-Output -Level:Warning
            return # don't throw exception, since this is a controlled scenario and we do not need stack exception tracing
        }
    }

    $splat = @{
        Uri = $null
        Body = $null
        Method = 'Put'
        Credential = $NcRestCredential
        Headers = @{"Accept"="application/json"}
        ContentType = "application/json; charset=UTF-8"
        TimeoutInSec = 30
    }

    $iDnsCredentialObject = @{
        ResourceId = 'iDnsUser'
        Properties = @{
            Type = 'UsernamePassword'
            UserName = $DnsForwarderCredential.UserName
            Value = $DnsForwarderCredential.GetNetworkCredential().Password
        }
    }

    $iDnsObject = @{
        ResourceId = 'configuration'
        Properties = @{
            Connections = $null
            Zone = $ZoneName
        }
    }

    $proxyPort = 53
    $dnsProxyServicePath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\Plugins\Vnet\InfraServices\DnsProxyService'
    $dnsRegServicePath = 'HKLM:\SYSTEM\CurrentControlSet\Services\DNSProxy\Parameters'
    $configureDnsProxyOnHosts = {
        param([string]$regpath1, [string]$regpath2, [string[]]$forwarderIp, [int]$port, [string]$proxyIP, [string]$mac)

        # create the registry key paths if they do not exist
        if (-NOT (Test-Path -Path $regpath1)) {
            $null = New-Item -Path $regpath1 -Force -ErrorAction Stop
        }

        if (-NOT (Test-Path -Path $regpath2)) {
            $null = New-Item -Path $regpath2 -Force -ErrorAction Stop
        }

        # create the corresponding registry keys
        # set the error action to silentlycontinue as this will generate errors if the property already exists
        $null = New-ItemProperty -Path $regpath1 -Name 'IP' -PropertyType 'String' -Value $proxyIP -ErrorAction SilentlyContinue
        $null = New-ItemProperty -Path $regpath1 -Name 'ProxyPort' -PropertyType 'DWORD' -Value $port -ErrorAction SilentlyContinue
        $null = New-ItemProperty -Path $regpath1 -Name 'Port' -PropertyType 'DWORD' -Value $port -ErrorAction SilentlyContinue
        $null = New-ItemProperty -Path $regpath1 -Name 'MAC' -PropertyType 'String' -Value $mac -ErrorAction SilentlyContinue
        $null = New-ItemProperty -Path $regpath2 -Name 'Forwarders' -PropertyType 'String' -Value $forwarderIp -ErrorAction SilentlyContinue

        # restart the NCHostAgent service to pick up the new registry settings configured in the previous step
        Restart-Service -Name 'NCHostAgent' -Force -ErrorAction Stop

        # create firewall rule to allow proxy to communicate with the VM and iDNS server
        Enable-NetFirewallRule -DisplayGroup 'DNS Proxy Firewall'
    }

    $configureTrustedHosts = {
        param([string]$param1)
        $trustedHosts = Get-Item -Path "WSMan:\LocalHost\Client\TrustedHosts"
        if ($trustedHosts.Value -notlike "*$param1*" -or $trustedHosts.Value -ne "*") {
            Set-Item "WSMan:\localhost\Client\TrustedHosts" -Value $param1 -Concatenate -Force
        }
    }

    try {
        $sdnFabricDetails = Get-SdnInfrastructureInfo -NetworkController $NetworkController -Credential $NcCredential -NcRestCredential $NcRestCredential

        # check to see if the DnsForwarderAddress is IP address(es)
        # if they are an IP address, we will need to configure the WinRM TrustedHosts on the NC nodes
        # otherwise the PUT operation to provision the iDNSServer/configuration will fail
        foreach ($obj in $DnsForwarderAddress) {
            $isIpAddress = ($obj -as [IPAddress]) -as [Bool]
            if ($isIpAddress) {
                "{0} is an ip address, which requires WinRM TrustedHosts to be configured on {1}." -f $obj, ($sdnFabricDetails.NetworkController -join ', ') | Trace-Output -Level:Warning
                $confirm = Confirm-UserInput
                if ($confirm) {
                    foreach ($node in $sdnFabricDetails.NetworkController) {
                        "Verifying and if required, adding {0} to TrustedHosts on {1}" -f $obj, $node | Trace-Output
                        Invoke-PSRemoteCommand -ComputerName $node -Credential $NcCredential -ScriptBlock $configureTrustedHosts -ArgumentList $obj
                    }

                    # after configuration of TrustedHosts, we want to perform a graceful failover of the vSwitch service
                    Move-SdnServiceFabricReplica -ServiceName 'fabric:/NetworkController/VSwitchService' -NetworkController $NetworkController -Credential $NcCredential
                }
                else {
                    # if the user opted to not configure, then prompt again to determine if they want to proceed regardless or abort out of the operation entirely
                    "Configuration of /iDnsServer/configuration may fail if TrustedHosts not already configured." | Trace-Output -Level:Warning
                    $confirm = Confirm-UserInput
                    if (-NOT $confirm) {
                        return
                    }
                }
            }
        }

        # perform the PUT operation to NC to create the credential object that will be used by NC to perform updates to DNS
        $resourceString = "/credentials/{0}" -f $iDnsCredentialObject.ResourceId
        "Creating {0} within Network Controller" -f $resourceString | Trace-Output
        $credentialEndpoint = Get-SdnApiEndpoint -NcUri $sdnFabricDetails.NcUrl -ResourceRef $resourceString -ApiVersion $sdnFabricDetails.RestApiVersion
        $splat.Body = ($iDnsCredentialObject | ConvertTo-Json -Depth 10)
        $splat.Uri = $credentialEndpoint
        Invoke-RestMethodWithRetry @splat
        if (-NOT (Confirm-ProvisioningStateSucceeded -Uri $credentialEndpoint -Credential $NcRestCredential -UseBasicParsing)) {
            throw New-Object System.Exception("Resource ProvisioningState is not succeeded")
        }

        # update the idnsobject to include the credential object that was created in the previous step
        $credential = Get-SdnResource -NcUri $sdnFabricDetails.NcUrl -Resource 'Credentials' -ResourceId 'iDnsUser' -Credential $NcRestCredential
        $connectionsObject = [Object]@{
            Credential = $credential
            CredentialType = $credential.properties.Type
            ManagementAddresses = $DnsForwarderAddress
        }

        $iDnsObject.Properties.Connections = @($connectionsObject)

        # perform PUT operation to NC to create the iDNS server configuration
        $resourceString = "/iDnsServer/configuration"
        "Creating {0} within Network Controller" -f $resourceString | Trace-Output

        $iDnsEndpoint = Get-SdnApiEndpoint -NcUri $sdnFabricDetails.NcUrl -ResourceRef $resourceString -ApiVersion $sdnFabricDetails.RestApiVersion
        $splat.Body = ($iDnsObject | ConvertTo-Json -Depth 10)
        $splat.Uri = $iDnsEndpoint
        Invoke-RestMethodWithRetry @splat
        if (-NOT (Confirm-ProvisioningStateSucceeded -Uri $iDnsEndpoint -Credential $NcRestCredential -UseBasicParsing)) {
            throw New-Object System.Exception("Resource ProvisioningState is not succeeded")
        }

        # once all the control plane has been configured, we need to push the registry settings to each of the hosts within the SDN fabric
        # so that the workloads can make use of the new iDNS server configuration
        $servers = Get-SdnServer -NcUri $sdnFabricDetails.NcUrl -Credential $NcRestCredential -ManagementAddressOnly
        foreach ($server in $servers) {
            "Configuring iDNS proxy on {0}" -f $server | Trace-Output
            Invoke-PSRemoteCommand -ComputerName $server -ScriptBlock $configureDnsProxyOnHosts `
            -ArgumentList @($dnsProxyServicePath, $dnsRegServicePath, $DnsForwarderAddress, $proxyPort, $ProxyIpAddress, $ProxyMacAddress)
        }

        "iDNS server configuration completed successfully" | Trace-Output
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
