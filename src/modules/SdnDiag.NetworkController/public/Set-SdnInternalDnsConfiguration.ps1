function Set-SdnInternalDnsConfiguration {
    <#
    .SYNOPSIS
        Configures the Internal DNS (iDNS) service to provide default name resolution services for tenant workloads.
    .DESCRIPTION
        Automates the configuration of iDNS by configuring the appropriate NB API endpoint, setting credentials and configuring the appropriate registry keys on the hypervisor servers.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER ZoneName
        The zone within DNS that will be used to host the iDNS records.
    .PARAMETER DnsForwarderAddress
        The FQDN or IP Address of the AD-Integrated DNS servers that will be used to service DNS requests for tenant workloads.
    .PARAMETER ProxyIpAddress
        The fixed IP address configured on the guest OS network interface if tenant chooses to use iDNS service. If omitted, defaults to 168.63.129.16.
    .PARAMETER ProxyMacAddress
    .PARAMETER Credential
        Specifies a user account that has appropriate permissions to hypervisor hosts to configure registry paths and keys and restart services. If omitted, defaults to current user.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to access the northbound NC API interface. If omitted, defaults to current user.
    .PARAMETER DnsForwarderCredential
        Specifies a user account that has appropriate permissions to the DNS Forwarders. This credential will be leveraged by Network Controller to create the DNS Zone and manage records.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

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
        $HostCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    $headers = @{"Accept"="application/json"}
    $content = "application/json; charset=UTF-8"
    $timeout = 30

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
            Connections = @{
                Credential = $null
                CredentialType = $null
                ManagementAddresses = $DnsForwarderAddress
            }
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
        New-Item -Path $regpath1 -Name 'IP' -PropertyType String -Value $proxyIP
        New-Item -Path $regpath1 -Name 'ProxyPort' -PropertyType DWORD -Value $port
        New-Item -Path $regpath1 -Name 'Port' -PropertyType DWORD -Value $port
        New-Item -Path $regpath1 -Name 'MAC' -PropertyType DWORD -Value $mac
        New-Item -Path $regpath2 -Name 'Forwarders' -PropertyType String -Value $forwarderIp

        # restart the NCHostAgent service to pick up the new registry settings configured in the previous step
        Restart-Service -Name 'NCHostAgent' -Force -ErrorAction Stop

        # create firewall rule to allow proxy to communicate with the VM and iDNS server
        Enable-NetFirewallRule -DisplayGroup 'DNS Proxy Firewall'
    }

    try {
        $discovery = Get-SdnDiscovery -NcUri $NcUri -Credential $NcRestCredential

        # perform the PUT operation to NC to create the credential object that will be used by NC to perform updates to DNS
        "Creating the iDnsUser credential object in Network Controller" | Trace-Output
        $credentialEndpoint = Get-SdnApiEndpoint -NcUri -ResourceName 'credentials' -ApiVersion $discovery.properties.currentRestVersion
        $iDnsCredentialObjectBody = $iDnsCredentialObject | ConvertTo-Json -Depth 10
        Invoke-RestMethodWithRetry -Uri $credentialEndpoint -Method 'PUT' -Body $iDnsCredentialObjectBody -Headers $headers -ContentType $content -Credential $NcRestCredential -TimeoutInSec $timeout

        $credential = Get-SdnResource -NcUri $NcUri -Resource 'Credentials' -ResourceId 'iDnsUser' -Credential $NcRestCredential
        if ($null -ieq $credential) {
            throw System.NullReferenceException("Unable to locate credential for iDnsUser")
        }

        # update the idnsobject to include the credential object that was created in the previous step
        $iDnsObject.Properties.Connections.Credential = $credential
        $iDnsObject.Properties.Connections.CredentialType = $credential.properties.Type

        # perform PUT operation to NC to create the iDNS server configuration
        "Configuring the iDNS Server configuration within Network Controller" | Trace-Output
        $iDnsEndpoint = Get-SdnApiEndpoint -NcUri $NcUri -ResourceRef '/iDnsServer' -ApiVersion $discovery.properties.currentRestVersion
        Invoke-RestMethodWithRetry -Uri $iDnsEndpoint -Method 'PUT' -Body $iDnsObjectBody -Headers $headers -ContentType $content -Credential $NcRestCredential -TimeoutInSec $timeout
        $iDnsConfig = Get-SdnResource -NcUri $NcUri -Resource 'IDNSServerConfig' -Credential $NcRestCredential
        if ($null -ieq $iDnsConfig) {
            throw System.NullReferenceException("Unable to locate iDNS configuration")
        }

        # once all the control plane has been configured, we need to push the registry settings to each of the hosts within the SDN fabric
        # so that the workloads can make use of the new iDNS server configuration
        $servers = Get-SdnServer -NcUri $NcUri -Credential $NcRestCredential -ManagementAddressOnly
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
