# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Import-Module $PSScriptRoot\SdnDiag.Common.psm1
Import-Module $PSScriptRoot\SdnDiag.NetworkController.FC.psm1
Import-Module $PSScriptRoot\SdnDiag.NetworkController.SF.psm1
Import-Module $PSScriptRoot\SdnDiag.Utilities.psm1

$configurationData = Import-PowerShellDataFile -Path "$PSScriptRoot\SdnDiag.Health.Config.psd1"
New-Variable -Name 'SdnDiagnostics_Health' -Scope 'Script' -Force -Value @{
    Cache = @{}
    Config = $configurationData
}

##########################
#### CLASSES & ENUMS #####
##########################

enum SdnHealthResult {
    PASS
    FAIL
    WARNING
}

class SdnHealth {
    [String]$Name = (Get-PSCallStack)[1].Command
    [SdnHealthResult]$Result = 'PASS'
    [DateTime]$OccurrenceTime = [System.DateTime]::UtcNow
    [Object]$Properties
    [String[]]$Remediation
}

class SdnFabricEnvObject {
    [String[]]$ComputerName
    [Uri]$NcUrl
    [Object]$Role
    [Object]$EnvironmentInfo
}

class SdnFabricHealthReport {
    [DateTime]$OccurrenceTime = [System.DateTime]::UtcNow
    [String]$Role
    [SdnHealthResult]$Result = 'PASS'
    [Object[]]$HealthValidation
}

##########################
#### ARG COMPLETERS ######
##########################

$argScriptBlock = @{
    Role = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $result = (Get-SdnFabricInfrastructureResult)
        if ([string]::IsNullOrEmpty($wordToComplete)) {
            return ($result.Role | Sort-Object -Unique)
        }

        return $result.Role | Where-Object {$_.Role -like "*$wordToComplete*"} | Sort-Object
    }
    Name = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $result = (Get-SdnFabricInfrastructureResult).HealthValidation
        if ([string]::IsNullOrEmpty($wordToComplete)) {
            return ($result.Name | Sort-Object -Unique)
        }

        return $result.Name | Where-Object {$_.Name -like "*$wordToComplete*"} | Sort-Object
    }
}

Register-ArgumentCompleter -CommandName 'Get-SdnFabricInfrastructureResult' -ParameterName 'Role' -ScriptBlock $argScriptBlock.Role
Register-ArgumentCompleter -CommandName 'Get-SdnFabricInfrastructureResult' -ParameterName 'Name' -ScriptBlock $argScriptBlock.Name

##########################
####### FUNCTIONS ########
##########################

function Get-HealthData {
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$Property,

        [Parameter(Mandatory = $true)]
        [System.String]$Id
    )

    $results = $script:SdnDiagnostics_Health.Config[$Property]
    return ($results[$Id])
}

function Test-EncapOverhead {
    <#
    .SYNOPSIS
        Retrieves the VMSwitch across servers in the dataplane to confirm that the network interfaces support EncapOverhead or JumboPackets
        and that the settings are configured as expected
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    [int]$encapOverheadExpectedValue = 160
    [int]$jumboPacketExpectedValue = 1674 # this is default 1514 MTU + 160 encap overhead
    $sdnHealthObject = [SdnHealth]::new()
    $array = @()

    try {
        "Validating the network interfaces across the SDN dataplane support Encap Overhead or Jumbo Packets" | Trace-Output

        $encapOverheadResults = Invoke-PSRemoteCommand -ComputerName $SdnEnvironmentObject.ComputerName -Credential $Credential -Scriptblock {Get-SdnNetAdapterEncapOverheadConfig}
        if($null -eq $encapOverheadResults){
            $sdnHealthObject.Result = 'FAIL'
        }
        else {
            foreach($object in ($encapOverheadResults | Group-Object -Property PSComputerName)){
                foreach($interface in $object.Group){
                    "[{0}] {1}" -f $object.Name, ($interface | Out-String -Width 4096) | Trace-Output -Level:Verbose

                    if($interface.EncapOverheadEnabled -eq $false -or $interface.EncapOverheadValue -lt $encapOverheadExpectedValue){
                        "EncapOverhead settings for {0} on {1} are disabled or not configured correctly" -f $interface.NetworkInterface, $object.Name | Trace-Output -Level:Verbose
                        $encapDisabled = $true
                    }

                    if($interface.JumboPacketEnabled -eq $false -or $interface.JumboPacketValue -lt $jumboPacketExpectedValue){
                        "JumboPacket settings for {0} on {1} are disabled or not configured correctly" -f $interface.NetworkInterface, $object.Name | Trace-Output -Level:Verbose
                        $jumboPacketDisabled = $true
                    }

                    # if both encapoverhead and jumbo packets are not set, this is indication the physical network cannot support VXLAN encapsulation
                    # and as such, environment would experience intermittent packet loss
                    if ($encapDisabled -and $jumboPacketDisabled) {
                        $sdnHealthObject.Result = 'FAIL'
                        $sdnHealthObject.Remediation += "Ensure EncapOverhead and JumboPacket for interface {0} on {1} are enabled and configured correctly." -f $interface.NetworkInterface, $object.Name

                        "EncapOverhead and JumboPacket for interface {0} on {1} are disabled or not configured correctly." -f $interface.NetworkInterface, $object.Name  | Trace-Output -Level:Error
                    }

                    $array += $interface
                }
            }

            $sdnHealthObject.Properties = $array
        }

        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-HostRootStoreNonRootCert {
    <#
    .SYNOPSIS
        Validate the Cert in Host's Root CA Store to detect if any Non Root Cert exist
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()
    $array = @()

    try {
        "Validating Certificates under Root CA Store" | Trace-Output

        $scriptBlock = {
            $nonRootCerts = @()
            $rootCerts = Get-ChildItem Cert:LocalMachine\Root
            foreach ($rootCert in $rootCerts) {
                if ($rootCert.Subject -ne $rootCert.Issuer) {
                    $certInfo = [PSCustomObject]@{
                        Thumbprint = $rootCert.Thumbprint
                        Subject    = $rootCert.Subject
                        Issuer     = $rootCert.Issuer
                    }

                    $nonRootCerts += $certInfo
                }
            }
            return $nonRootCerts
        }

        foreach($node in $SdnEnvironmentObject.ComputerName){
            $nonRootCerts = Invoke-PSRemoteCommand -ComputerName $node -Credential $Credential -ScriptBlock $scriptBlock -PassThru
            # If any node have Non Root Certs in Trusted Root Store. Issue detected.
            if($nonRootCerts.Count -gt 0){
                $sdnHealthObject.Result = 'FAIL'

                $object = [PSCustomObject]@{
                    ComputerName = $node
                    NonRootCerts = $nonRootCerts
                }

                foreach($nonRootCert in $nonRootCerts) {
                    $sdnHealthObject.Remediation += "Remove Certificate Thumbprint:{0} Subject:{1} from Host:{2}" -f $nonRootCert.Thumbprint, $nonRootCert.Subject, $node
                }

                $array += $object
            }
        }

        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-MuxBgpConnectionState {
    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate
    )

    $ncRestParams = @{
        NcUri = $SdnEnvironmentObject.NcUrl
    }
    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $ncRestParams.Add('NcRestCredential', $NcRestCredential)
        }
    }

    $sdnHealthObject = [SdnHealth]::new()
    $array = @()

    $netConnectionExistsScriptBlock = {
        param([Parameter(Position = 0)][String]$arg0)
        $tcpConnection = Get-NetTCPConnection -RemotePort 179 -RemoteAddress $arg0 -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Established" }
        if ($tcpConnection) {
            return $true
        }
    }

    try {
        "Validating the BGP connectivity between LoadBalancerMuxes and Top of Rack (ToR) Switches." | Trace-Output
        $loadBalancerMux = Get-SdnLoadBalancerMux @ncRestParams

        # if no load balancer muxes configured within the environment, return back the health object to caller
        if ($null -ieq $loadBalancerMux) {
            return $sdnHealthObject
        }

        # enumerate through the load balancer muxes in the environment and validate the BGP connection state
        foreach ($mux in $loadBalancerMux) {
            $virtualServer = Get-SdnResource @ncRestParams -ResourceRef $mux.properties.virtualServer.resourceRef
            [string]$virtualServerConnection = $virtualServer.properties.connections[0].managementAddresses
            $peerRouters = $mux.properties.routerConfiguration.peerRouterConfigurations.routerIPAddress
            foreach ($router in $peerRouters) {
                $connectionExists = Invoke-PSRemoteCommand -ComputerName $virtualServerConnection -Credential $Credential -ScriptBlock $netConnectionExistsScriptBlock -ArgumentList $router
                if (-NOT $connectionExists) {
                    "{0} is not connected to {1}" -f $virtualServerConnection, $router | Trace-Output -Level:Error
                    $sdnHealthObject.Result = 'FAIL'
                    $sdnHealthObject.Remediation += "Fix BGP Peering between $($virtualServerConnection) and $($router)."

                    # create a custom object to store the load balancer mux and the router that it is not connected to
                    # this will be added to the array
                    $object = [PSCustomObject]@{
                        LoadBalancerMux = $virtualServerConnection
                        TopOfRackSwitch = $router
                    }

                    $array += $object
                }
                else {
                    "{0} is connected to {1}" -f $virtualServerConnection, $router | Trace-Output -Level:Verbose
                }
            }
        }

        # if the array is not empty, add it to the health object
        if ($array) {
            $sdnHealthObject.Properties = $array
        }

        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-NcHostAgentConnectionToApiService {
    <#
    .SYNOPSIS
        Validates the TCP connection between Server and primary replica of Api service within Network Controller.
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate
    )

    $ncRestParams = @{
        NcUri = $SdnEnvironmentObject.NcUrl
    }
    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $ncRestParams.Add('NcRestCredential', $NcRestCredential)
        }
    }

    $sdnHealthObject = [SdnHealth]::new()
    $array = @()

    $netConnectionExistsScriptBlock = {
        $tcpConnection = Get-NetTCPConnection -RemotePort 6640 -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Established" }
        if ($tcpConnection) {
            return $true
        }
    }

    try {
        "Validating connectivity between Server and primary replica of API service within Network Controller" | Trace-Output
        $servers = Get-SdnServer @ncRestParams

        # if no load balancer muxes configured within the environment, return back the health object to caller
        if ($null -ieq $servers) {
            return $sdnHealthObject
        }

        # get the current primary replica of Network Controller
        # if we cannot return the primary replica, then something is critically wrong with Network Controller
        # in which case we should mark this test as failed and return back to the caller with guidance to fix the SlbManagerService
        $primaryReplicaNode = Get-SdnServiceFabricReplica -NetworkController $SdnEnvironmentObject.EnvironmentInfo.NetworkController[0] -ServiceTypeName 'ApiService' -Credential $Credential -Primary
        if ($null -ieq $primaryReplicaNode) {
            "Unable to return primary replica of ApiService" | Trace-Output -Level:Error
            $sdnHealthObject.Result = 'FAIL'
            $sdnHealthObject.Remediation = "Fix the primary replica of ApiService within Network Controller."
            return $sdnHealthObject
        }

        # enumerate through the servers in the environment and validate the TCP connection state
        # we expect the NCHostAgent to have an active connection to ApiService within Network Controller via port 6640, which informs
        # Network Controller that the host is operational and ready to receive policy configuration updates
        foreach ($server in $servers) {
            [System.Array]$connectionAddress = Get-SdnServer @ncRestParams -ResourceId $server.resourceId -ManagementAddressOnly
            $connectionExists = Invoke-PSRemoteCommand -ComputerName $connectionAddress[0] -Credential $Credential -ScriptBlock $netConnectionExistsScriptBlock
            if (-NOT $connectionExists) {
                "{0} is not connected to ApiService of Network Controller" -f $server.resourceRef | Trace-Output -Level:Error
                $sdnHealthObject.Result = 'FAIL'
                $sdnHealthObject.Remediation += "Ensure NCHostAgent service is started. Investigate and fix TCP connectivity or x509 authentication between $($primaryReplicaNode.ReplicaAddress) and $($server.resourceRef)."

                $object = [PSCustomObject]@{
                    Server = $server.resourceRef
                    ApiPrimaryReplica = $primaryReplicaNode.ReplicaAddress
                }

                $array += $object
            }
            else {
                "{0} is connected to {1}" -f $server.resourceRef, $primaryReplicaNode.ReplicaAddress | Trace-Output -Level:Verbose
            }
        }

        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-NcUrlNameResolution {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()

    try {
        "Validate that the Network Controller NB API URL resolves to the correct IP address" | Trace-Output

        $ncApiReplicaPrimary = Get-SdnServiceFabricReplica -NetworkController $SdnEnvironmentObject.ComputerName[0] -Credential $Credential -ServiceTypeName 'ApiService' -Primary
        if ($null -eq $ncApiReplicaPrimary) {
            "Unable to find the primary replica for the ApiService" | Trace-Output -Level:Warning
            return $sdnHealthObject
        }

        $networkController = Get-SdnNetworkController -NetworkController $SdnEnvironmentObject.ComputerName[0] -Credential $Credential
        if ($null -eq $networkController) {
            "Unable to retrieve results from Get-SdnNetworkController" | Trace-Output -Level:Warning
            return $sdnHealthObject
        }

        # depending on the configuration returned, will determine if we need to use the RestIPAddress or RestName
        $nbApiName = $networkController.ServerCertificate.Subject.Split('=')[1].Trim()

        if ($networkController.RestIPAddress) {
            $expectedIPAddress = $($networkController.RestIPAddress).Split('/')[0].Trim() # we expect to be in IP/CIDR format
            "Network Controller is configured with static RestIPAddress: {0}" -f $expectedIPAddress | Trace-Output -Level:Verbose
        }
        else {
            "Network Controller is configured with RestName" | Trace-Output -Level:Verbose
            $ncNodeName = $ncApiReplicaPrimary.ReplicaAddress.Split(':')[0].Trim()
            $isIpAddress = [System.Net.IPAddress]::TryParse($ncNodeName, [ref]$null)
            if ($isIpAddress) {
                $expectedIPAddress = $ncNodeName.ToString()
            }
            else {
                $dnsResultNetworkControllerNode = Resolve-DnsName -Name $ncNodeName -NoHostsFile -ErrorAction SilentlyContinue
                if ($null -ieq $dnsResultNetworkControllerNode) {
                    "Unable to resolve IP address for {0}" -f $ncNodeName | Trace-Output -Level:Warning
                    return $sdnHealthObject
                }
                else {
                    $expectedIPAddress = $dnsResultNetworkControllerNode.IPAddress
                    "ApiService replica primary is hosted on {0} with an IP address of {1}" -f $ncApiReplicaPrimary.ReplicaAddress, $expectedIPAddress | Trace-Output -Level:Verbose
                }
            }
        }

        # in this scenario, the certificate is using an IP address as the subject, so we will need to compare the IP address to the expected IP address
        # if they match, we will return a success
        $isIpAddress = [System.Net.IPAddress]::TryParse($nbApiName, [ref]$null)
        if ($isIpAddress -and ($nbApiName -ieq $expectedIPAddress)) {
            return $sdnHealthObject
        }

        # perform some DNS resolution to ensure that the NB API URL resolves to the correct IP address
        $dnsResult = Resolve-DnsName -Name $nbApiName -NoHostsFile -ErrorAction SilentlyContinue
        if ($null -ieq $dnsResult) {
            $sdnHealthObject.Result = 'FAIL'

            "Unable to resolve DNS name for {0}" -f $nbApiName | Trace-Output -Level:Warning
            return $sdnHealthObject
        }
        elseif ($dnsResult[0].IPAddress -ine $expectedIPAddress) {
            $sdnHealthObject.Result = 'FAIL'
            $sdnHealthObject.Remediation = 'Ensure that the DNS name for the Network Controller NB API URL resolves to the correct IP address.'

            "DNS name for {0} resolves to {1} instead of {2}" -f $nbApiName, $dnsResult[0].IPAddress, $expectedIPAddress | Trace-Output -Level:Warning
            return $sdnHealthObject
        }

        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-NetworkControllerCertCredential {
    <#
    .SYNOPSIS
        Query the NC Cert credential used to connect to SDN Servers, ensure cert exist.
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate
    )

    $ncRestParams = @{
        NcUri = $SdnEnvironmentObject.NcUrl
    }
    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $ncRestParams.Add('NcRestCredential', $NcRestCredential)
        }
    }

    $sdnHealthObject = [SdnHealth]::new()
    $arrayList = [System.Collections.ArrayList]::new()

    try {
        "Validate cert credential resource of SDN Servers. Ensure certificate exists on each of the Network Controller " | Trace-Output

        # enumerate each server's conection->credential object into the array
        $servers = Get-SdnServer @ncRestParams
        $serverCredentialRefs = [System.Collections.Hashtable]::new()
        foreach ($server in $servers) {
            # find the first connection with credential type of X509Certificate
            $serverConnection = $server.properties.connections | Where-Object {$_.credentialType -ieq "X509Certificate" -or $_.credentialType -ieq "X509CertificateSubjectName"} | Select-Object -First 1;
            if ($null -ne $serverConnection) {
                $credRef = $serverConnection.credential[0].resourceRef
                "Adding credential {0} for server {1} for validation" -f $credRef, $serverConnection.managementAddresses[0] | Trace-Output -Level:Verbose
                if ($null -ne $credRef) {
                    if (-NOT $serverCredentialRefs.ContainsKey($credRef)) {
                        $serverList = [System.Collections.ArrayList]::new()
                        $serverCredentialRefs.Add($credRef, $serverList)
                    }

                    [void]$serverCredentialRefs[$credRef].Add($server)
                }
            }
        }

        # iterate the credential object to validate certificate on each NC
        foreach ($credRef in $serverCredentialRefs.Keys) {
            $credObj = Get-SdnResource @ncRestParams -ResourceRef $credRef
            if ($null -ne $credObj) {
                $thumbPrint = $credObj.properties.value
                $scriptBlock = {
                    param([Parameter(Position = 0)][String]$param1)

                    if (-NOT (Test-Path -Path Cert:\LocalMachine\My\$param1)) {
                        return $false
                    }
                    else {
                        return $true
                    }
                }

                # invoke command on each NC seperately so to record which NC missing certificate
                foreach ($nc in $SdnEnvironmentObject.ComputerName) {
                    "Validating certificate [{0}] on NC {1}" -f $thumbPrint, $nc | Trace-Output -Level:Verbose
                    $result = Invoke-PSRemoteCommand -ComputerName $nc -Credential $Credential -ScriptBlock $scriptBlock -ArgumentList $thumbPrint
                    if ($result -ne $true) {
                        # if any NC missing certificate, it indicate issue detected
                        $sdnHealthObject.Result = 'FAIL'
                        $sdnHealthObject.Remediation += "Install certificate [$thumbPrint] on Network Controller [$nc]"
                        $object = [PSCustomObject]@{
                            NetworkController  = $nc
                            CertificateMissing = $thumbPrint
                            AffectedServers    = $serverCredentialRefs[$credRef]
                        }

                        [void]$arrayList.Add($object)
                    }
                }

            }
        }

        $sdnHealthObject.Properties = $arrayList
        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-NetworkInterfaceAPIDuplicateMacAddress {
    <#
    .SYNOPSIS
        Validate there are no adapters within the Network Controller Network Interfaces API that are duplicate.
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate
    )

    $ncRestParams = @{
        NcUri = $SdnEnvironmentObject.NcUrl
    }
    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $ncRestParams.Add('NcRestCredential', $NcRestCredential)
        }
    }

    $sdnHealthObject = [SdnHealth]::new()
    $array = @()

    try {
        "Validate no duplicate MAC addresses for network interfaces in Network Controller" | Trace-Output

        $networkInterfaces = Get-SdnResource @ncRestParams -Resource:NetworkInterfaces
        if($null -eq $networkInterfaces){
            # if there are no network interfaces, then there is nothing to validate
            # pass back the health object to the caller
            return $sdnHealthObject
        }

        $duplicateObjects = $networkInterfaces.properties | Group-Object -Property privateMacAddress | Where-Object {$_.Count -ge 2}
        if($duplicateObjects){
            $sdnHealthObject.Result = 'FAIL'

            # since there can be multiple grouped objects, we need to enumerate each duplicate group
            foreach($obj in $duplicateObjects){
                $sdnHealthObject.Remediation += "Remove the duplicate MAC addresses for $($obj.Name) within Network Controller Network Interfaces"

                $duplicateInterfaces = $networkInterfaces | Where-Object {$_.properties.privateMacAddress -eq $obj.Name}
                $array += $duplicateInterfaces

                "Located {0} virtual machines associated with MAC address {1}:`r`n`n{2}`r`n" -f $obj.Count, $obj.Name, `
                    ($duplicateInterfaces `
                    | Select-Object @{n="ResourceRef";e={"`t$($_.resourceRef)"}} `
                    | Select-Object -ExpandProperty ResourceRef `
                    | Out-String `
                ) | Trace-Output -Level:Error
            }
        }

        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-ProviderNetwork {
    <#
    .SYNOPSIS
        Performs ICMP tests across the computers defined to confirm that jumbo packets are able to successfully traverse between the provider addresses on each host
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()
    $array = @()

    try {
        "Validating Provider Address network has connectivity across the SDN dataplane" | Trace-Output

        $providerAddresses = (Get-SdnProviderAddress -ComputerName $SdnEnvironmentObject.ComputerName -Credential $Credential).ProviderAddress
        if ($null -eq $providerAddresses){
            "No provider addresses were found on the hosts." | Trace-Output
        }
        else {
            $connectivityResults = Invoke-PSRemoteCommand -ComputerName $SdnEnvironmentObject.ComputerName -Credential $Credential -Scriptblock {
                param([Parameter(Position = 0)][String[]]$param1)
                Test-SdnProviderAddressConnectivity -ProviderAddress $param1
            } -ArgumentList $providerAddresses

            foreach($computer in $connectivityResults | Group-Object PSComputerName){
                foreach($destinationAddress in $computer.Group){
                    $jumboPacketResult = $destinationAddress | Where-Object {$_.BufferSize -gt 1472}
                    $standardPacketResult = $destinationAddress | Where-Object {$_.BufferSize -le 1472}

                    if($destinationAddress.Status -ine 'Success'){
                        $sdnHealthObject.Result = 'FAIL'

                        # if both jumbo and standard icmp tests fails, indicates a failure in the physical network
                        if($jumboPacketResult.Status -ieq 'Failure' -and $standardPacketResult.Status -ieq 'Failure'){
                            $remediationMsg = "Ensure ICMP enabled on {0} and {1}. If issue persists, investigate physical network." -f $destinationAddress[0].DestinationAddress, $destinationAddress[0].SourceAddress
                            $sdnHealthObject.Remediation += $remediationMsg

                            "Cannot ping {0} from {1} ({2})." `
                            -f $destinationAddress[0].DestinationAddress, $computer.Name, $destinationAddress[0].SourceAddress | Trace-Output -Level:Error
                        }

                        # if standard MTU was success but jumbo MTU was failure, indication that jumbo packets or encap overhead has not been setup and configured
                        # either on the physical nic or within the physical switches between the provider addresses
                        if($jumboPacketResult.Status -ieq 'Failure' -and $standardPacketResult.Status -ieq 'Success'){
                            $remediationMsg += "Ensure the physical network between {0} and {1} configured to support VXLAN or NVGRE encapsulated packets with minimum MTU of 1660." `
                            -f $destinationAddress[0].DestinationAddress, $destinationAddress[0].SourceAddress
                            $sdnHealthObject.Remediation += $remediationMsg

                            "Cannot send jumbo packets to {0} from {1} ({2})." `
                            -f $destinationAddress[0].DestinationAddress, $computer.Name, $destinationAddress[0].SourceAddress | Trace-Output -Level:Error
                        }
                    }
                    else {
                        "Successfully sent jumbo packet to {0} from {1} ({2})" `
                        -f $destinationAddress[0].DestinationAddress, $computer.Name, $destinationAddress[0].SourceAddress | Trace-Output
                    }

                    $array += $destinationAddress
                }
            }
        }

        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-ResourceConfigurationState {
    <#
    .SYNOPSIS
        Validate that the configurationState of the resources.
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate
    )

    $ncRestParams = @{
        NcUri = $SdnEnvironmentObject.NcUrl
    }
    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $ncRestParams.Add('NcRestCredential', $NcRestCredential)
        }
    }

    $sdnHealthObject = [SdnHealth]::new()
    $array = @()

    try {
        "Validating configuration state of {0}" -f $SdnEnvironmentObject.Role.ResourceName | Trace-Output

        $sdnResources = Get-SdnResource @ncRestParams -Resource $SdnEnvironmentObject.Role.ResourceName
        foreach ($object in $sdnResources) {

            # if we have a resource that is not in a success state, we will skip validation
            # as we do not expect configurationState to be accurate if provisioningState is not Success
            if ($object.properties.provisioningState -ine 'Succeeded') {
                continue
            }

            # examine the configuration state of the resources and display errors to the screen
            $errorMessages = @()
            switch ($object.properties.configurationState.Status) {
                'Warning' {
                    # if we already have a failure, we will not change the result to warning
                    if ($sdnHealthObject.Result -ne 'FAIL') {
                        $sdnHealthObject.Result = 'WARNING'
                    }

                    $traceLevel = 'Warning'
                }

                'Failure' {
                    $sdnHealthObject.Result = 'FAIL'
                    $traceLevel = 'Error'
                }

                'InProgress' {
                    # if we already have a failure, we will not change the result to warning
                    if ($sdnHealthObject.Result -ne 'FAIL') {
                        $sdnHealthObject.Result = 'WARNING'
                    }

                    $traceLevel = 'Warning'
                }

                'Uninitialized' {
                    # in scenarios where state is redundant, we will not fail the test
                    if ($object.properties.state -ieq 'Redundant') {
                        # do nothing
                    }
                    else {
                        # if we already have a failure, we will not change the result to warning
                        if ($sdnHealthObject.Result -ne 'FAIL') {
                            $sdnHealthObject.Result = 'WARNING'
                        }

                        $traceLevel = 'Warning'
                    }
                }

                default {
                    $traceLevel = 'Verbose'
                }
            }

            if ($object.properties.configurationState.detailedInfo) {
                foreach ($detail in $object.properties.configurationState.detailedInfo) {
                    switch ($detail.code) {
                        'Success' {
                            # do nothing
                        }

                        default {
                            $errorMessages += $detail.message
                            try {
                                $errorDetails = Get-HealthData -Property 'ConfigurationStateErrorCodes' -Id $detail.code
                                $sdnHealthObject.Remediation += "[{0}] {1}" -f $object.resourceRef, $errorDetails.Action
                            }
                            catch {
                                "Unable to locate remediation actions for {0}" -f $detail.code | Trace-Output -Level:Warning
                                $remediationString = "[{0}] Examine the configurationState property to determine why configuration failed." -f $object.resourceRef
                                $sdnHealthObject.Remediation += $remediationString
                            }
                        }
                    }
                }

                # print the overall configuration state to screen, with each of the messages that were captured
                # as part of the detailedinfo property
                if ($errorMessages) {
                    $msg = "{0} is reporting configurationState status {1}:`n`t- {2}" -f $object.resourceRef, $object.properties.configurationState.Status, ($errorMessages -join "`n`t- ")
                }
                else {
                    $msg = "{0} is reporting configurationState status {1}" -f $object.resourceRef, $object.properties.configurationState.Status
                }

                $msg | Trace-Output -Level $traceLevel.ToString()
            }

            $details = [PSCustomObject]@{
                resourceRef        = $object.resourceRef
                configurationState = $object.properties.configurationState
            }

            $array += $details
        }

        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-ResourceProvisioningState {
    <#
    .SYNOPSIS
        Validate that the provisioningState of the resources.
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate
    )

    $ncRestParams = @{
        NcUri = $SdnEnvironmentObject.NcUrl
    }
    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $ncRestParams.Add('NcRestCredential', $NcRestCredential)
        }
    }

    $sdnHealthObject = [SdnHealth]::new()
    $array = @()

    try {
        "Validating provisioning state of {0}" -f $SdnEnvironmentObject.Role.ResourceName | Trace-Output

        $sdnResources = Get-SdnResource @ncRestParams -Resource $SdnEnvironmentObject.Role.ResourceName
        foreach ($object in $sdnResources) {
            # examine the provisioning state of the resources and display errors to the screen
            $msg = "{0} is reporting provisioning state: {1}" -f $object.resourceRef, $object.properties.provisioningState

            switch ($object.properties.provisioningState) {
                'Failed' {
                    $sdnHealthObject.Result = 'FAIL'
                    $msg | Trace-Output -Level:Error

                    $sdnHealthObject.Remediation += "[$($object.resourceRef)] Examine the Network Controller logs to determine why provisioning is $($object.properties.provisioningState)."
                }

                'Updating' {
                    # if we already have a failure, we will not change the result to warning
                    if ($sdnHealthObject.Result -ne 'FAIL') {
                        $sdnHealthObject.Result = 'WARNING'
                    }

                    # since we do not know what operations happened prior to this, we will log a warning
                    # and ask the user to monitor the provisioningState
                    $msg | Trace-Output -Level:Warning
                    $sdnHealthObject.Remediation += "[$($object.resourceRef)] Is reporting $($object.properties.provisioningState). Monitor to ensure that provisioningState moves to Succeeded."
                }

                default {
                    # this should cover scenario where provisioningState is 'Deleting' or Succeeded
                    $msg | Trace-Output -Level:Verbose
                }
            }

            $details = [PSCustomObject]@{
                resourceRef       = $object.resourceRef
                provisioningState = $object.properties.provisioningState
            }

            $array += $details
        }

        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-ScheduledTaskEnabled {
    <#
    .SYNOPSIS
        Ensures the scheduled task responsible for etl compression is enabled and running
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()
    $array = @()

    $scriptBlock = {

        $object = [PSCustomObject]@{
            TaskName = 'SDN Diagnostics Task'
            State = $null
        }

        try {
            # check to see if logging is enabled on the registry key
            # if it is not, return the object with the state set to 'Logging Disabled'
            $isLoggingEnabled = Get-ItemPropertyValue -Path "HKLM:\Software\Microsoft\NetworkController\Sdn\Diagnostics\Parameters" -Name 'IsLoggingEnabled'
            if (-NOT $isLoggingEnabled ) {
                $object.State = 'Logging Disabled'
                return $object
            }

            $result = Get-ScheduledTask -TaskName 'SDN Diagnostics Task' -ErrorAction Stop
            if ($result) {
                $object.State = $result.State.ToString()
                return $object
            }
        }
        catch {
            # if the scheduled task does not exist, return the object with the state set to 'Not Found'
            $object.State = 'Not Found'
            return $object
        }
    }

    try {
        $scheduledTaskReady = Invoke-PSRemoteCommand -ComputerName $SdnEnvironmentObject.ComputerName -Credential $Credential -ScriptBlock $scriptBlock -AsJob -PassThru
        foreach ($result in $scheduledTaskReady) {
            switch ($result.State) {
                'Logging Disabled' {
                    "SDN Diagnostics Task is not available on {0} because logging is disabled." -f $result.PSComputerName | Trace-Output -Level:Verbose
                }
                'Not Found' {
                    "Unable to locate SDN Diagnostics Task on {0}." -f $result.PSComputerName | Trace-Output -Level:Error
                    $sdnHealthObject.Result = 'FAIL'
                }
                'Disabled' {
                    "SDN Diagnostics Task is disabled on {0}." -f $result.PSComputerName | Trace-Output -Level:Error
                    $sdnHealthObject.Result = 'FAIL'
                    $sdnHealthObject.Remediation += "Use 'Repair-SdnDiagnosticsScheduledTask' to enable the 'SDN Diagnostics Task' scheduled task on $($result.PSComputerName)."
                }
                default {
                    "SDN Diagnostics Task is {0} on {1}." -f $result.State, $result.PSComputerName | Trace-Output -Level:Verbose
                }
            }

            $array += [PSCustomObject]@{
                State = $result.State
                Computer = $result.PSComputerName
            }
        }

        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-ServerHostId {
    <#
    .SYNOPSIS
        Queries the NCHostAgent HostID registry key value across the hypervisor hosts to ensure the HostID matches known InstanceID results from NC Servers API.
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate
    )

    $ncRestParams = @{
        NcUri = $SdnEnvironmentObject.NcUrl
    }
    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $ncRestParams.Add('NcRestCredential', $NcRestCredential)
        }
    }

    $sdnHealthObject = [SdnHealth]::new()
    $array = @()

    try {
        "Validating Server HostID registry matches known InstanceIDs from Network Controller Servers API." | Trace-Output

        $scriptBlock = {
            $result = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters' -Name 'HostId' -ErrorAction SilentlyContinue
            return $result.HostID
        }

        $servers = Get-SdnResource @ncRestParams -Resource $SdnEnvironmentObject.Role.ResourceName
        $hostId = Invoke-PSRemoteCommand -ComputerName $SdnEnvironmentObject.ComputerName -Credential $Credential -ScriptBlock $scriptBlock -AsJob -PassThru
        foreach($id in $hostId){
            if($id -inotin $servers.instanceId){
                "{0}'s HostID {1} does not match known instanceID results in Network Controller Server REST API" -f $id.PSComputerName, $id | Trace-Output -Level:Error
                $sdnHealthObject.Result = 'FAIL'
                $sdnHealthObject.Remediation += "Update the HostId registry key on $($id.PSComputerName) to match the InstanceId of the Server resource in Network Controller"

                $object = [PSCustomObject]@{
                    HostID = $id
                    Computer = $id.PSComputerName
                }

                $array += $object
            }
            else {
                "{0}'s HostID {1} matches known InstanceID in Network Controller Server REST API" -f $id.PSComputerName, $id | Trace-Output -Level:Verbose
            }
        }

        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-ServiceFabricApplicationHealth {
    <#
    .SYNOPSIS
        Validate the health of the Network Controller application within Service Fabric.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()

    try {
        "Validating the Service Fabric Application Health for Network Controller" | Trace-Output

        $ncNodes = Get-SdnServiceFabricNode -NetworkController $SdnEnvironmentObject.ComputerName[0] -Credential $credential
        if($null -eq $ncNodes){
            throw New-Object System.NullReferenceException("Unable to retrieve service fabric nodes")
        }

        $applicationHealth = Get-SdnServiceFabricApplicationHealth -NetworkController $SdnEnvironmentObject.ComputerName[0] -Credential $Credential
        if ($applicationHealth.AggregatedHealthState -ine 'Ok') {
            $sdnHealthObject.Result = 'FAIL'
            $sdnHealthObject.Remediation += "Examine the Service Fabric Application Health for Network Controller to determine why the health is not OK."
        }

        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-ServiceFabricClusterHealth {
    <#
    .SYNOPSIS
        Validate the health of the Network Controller cluster within Service Fabric.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()

    try {
        "Validating the Service Fabric Cluster Health for Network Controller" | Trace-Output

        $ncNodes = Get-SdnServiceFabricNode -NetworkController $SdnEnvironmentObject.ComputerName[0] -Credential $credential
        if($null -eq $ncNodes){
            throw New-Object System.NullReferenceException("Unable to retrieve service fabric nodes")
        }

        $clusterHealth = Get-SdnServiceFabricClusterHealth -NetworkController $SdnEnvironmentObject.ComputerName[0] -Credential $Credential
        if ($clusterHealth.AggregatedHealthState -ine 'Ok') {
            $sdnHealthObject.Result = 'FAIL'
            $sdnHealthObject.Remediation += "Examine the Service Fabric Cluster Health for Network Controller to determine why the health is not OK."
        }

        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-ServiceFabricNodeStatus {
    <#
    .SYNOPSIS
        Validate the health of the Network Controller nodes within Service Fabric.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()

    try {
        "Validating the Service Fabric Nodes for Network Controller" | Trace-Output

        $ncNodes = Get-SdnServiceFabricNode -NetworkController $SdnEnvironmentObject.ComputerName[0] -Credential $credential
        if($null -eq $ncNodes){
            throw New-Object System.NullReferenceException("Unable to retrieve service fabric nodes")
        }

        foreach ($node in $ncNodes) {
            if ($node.NodeStatus -ine 'Up') {
                $sdnHealthObject.Result = 'FAIL'
                $sdnHealthObject.Remediation = 'Examine the Service Fabric Nodes for Network Controller to determine why the node is not Up.'
            }
        }

        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-ServiceFabricPartitionDatabaseSize {
    <#
    .SYNOPSIS
        Validate the Service Fabric partition size for each of the services running on Network Controller.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()
    $array = @()

    try {
        "Validate the size of the Service Fabric Partition Databases for Network Controller services" | Trace-Output

        $ncNodes = Get-SdnServiceFabricNode -NetworkController $SdnEnvironmentObject.ComputerName[0] -Credential $credential
        if($null -eq $ncNodes){
            throw New-Object System.NullReferenceException("Unable to retrieve service fabric nodes")
        }

        foreach($node in $ncNodes){
            $ncApp = Invoke-SdnServiceFabricCommand -NetworkController $SdnEnvironmentObject.ComputerName[0] -Credential $Credential -ScriptBlock {
                param([Parameter(Position = 0)][String]$param1)

                # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
                $null = Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null
                Get-ServiceFabricDeployedApplication -ApplicationName 'fabric:/NetworkController' -NodeName $param1
            } -ArgumentList @($node.NodeName.ToString())

            $ncAppWorkDir = $ncApp.WorkDirectory
            if($null -eq $ncAppWorkDir){
                throw New-Object System.NullReferenceException("Unable to retrieve working directory path")
            }

            # Only stateful service have the database file
            $ncServices = Get-SdnServiceFabricService -NetworkController $SdnEnvironmentObject.ComputerName[0] -Credential $Credential | Where-Object {$_.ServiceKind -eq "Stateful"}

            foreach ($ncService in $ncServices){
                $replica = Get-SdnServiceFabricReplica -NetworkController $SdnEnvironmentObject.ComputerName[0] -ServiceName $ncService.ServiceName -Credential $Credential | Where-Object {$_.NodeName -eq $node.NodeName}
                $imosStorePath = Join-Path -Path $ncAppWorkDir -ChildPath "P_$($replica.PartitionId)\R_$($replica.ReplicaId)\ImosStore"
                $imosStoreFile = Invoke-PSRemoteCommand -ComputerName $node.NodeName -Credential $Credential -ScriptBlock {
                    param([Parameter(Position = 0)][String]$param1)
                    if (Test-Path -Path $param1) {
                        return (Get-Item -Path $param1)
                    }
                    else {
                        return $null
                    }
                } -ArgumentList @($imosStorePath)

                if($null -ne $imosStoreFile){
                    $formatedByteSize = Format-ByteSize -Bytes $imosStoreFile.Length

                    $imosInfo = [PSCustomObject]@{
                        Node = $node.NodeName
                        Service = $ncService.ServiceName
                        ImosSize = $formatedByteSize.GB
                    }

                    # if the imos database file exceeds 4GB, want to indicate failure as it should not grow to be larger than this size
                    # need to perform InvariantCulture to ensure that the decimal separator is a period
                    if([float]::Parse($formatedByteSize.GB, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture) -gt 4){
                        "[{0}] Service {1} is reporting {2} GB in size" -f $node.NodeName, $ncService.ServiceName, $formatedByteSize.GB | Trace-Output -Level:Warning

                        $sdnHealthObject.Result = 'FAIL'
                        $sdnHealthObject.Remediation = "Engage Microsoft CSS for further support"
                    }
                    else {
                        "[{0}] Service {1} is reporting {2} GB in size" -f $node.NodeName, $ncService.ServiceName, $formatedByteSize.GB | Trace-Output -Level:Verbose
                    }

                    $array += $imosInfo
                }
                else {
                    "No ImosStore file for service {0} found on node {1} from {2}" -f $ncService.ServiceName, $node.NodeName, $imosStorePath | Trace-Output -Level:Warning
                }
            }
        }

        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-ServiceState {
    <#
    .SYNOPSIS
        Confirms that critical services for gateway are running
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()
    $array = @()
    $serviceStateResults = @()

    try {
        [string[]]$services = $SdnEnvironmentObject.Role.Properties.Services.Keys
        if ([string]::IsNullOrEmpty($services)) {
            return $sdnHealthObject
        }

        "Validating {0} service state for {1}" -f ($services -join ', '), ($SdnEnvironmentObject.ComputerName -join ', ') | Trace-Output

        $scriptBlock = {
            param([Parameter(Position = 0)][String]$param1)

            $result = Get-Service -Name $param1 -ErrorAction SilentlyContinue
            return $result
        }

        foreach ($service in $services) {
            $serviceStateResults += Invoke-PSRemoteCommand -ComputerName $SdnEnvironmentObject.ComputerName -Credential $Credential -Scriptblock $scriptBlock -ArgumentList $service
        }

        foreach($result in $serviceStateResults){
            $array += $result

            if($result.Status -ine 'Running'){
                $sdnHealthObject.Result = 'FAIL'
                $sdnHealthObject.Remediation += "Start $($result.Name) service on $($result.PSComputerName)"

                "{0} is {1} on {2}" -f $result.Name, $result.Status, $result.PSComputerName | Trace-Output -Level:Error
            }
            else {
                "{0} is {1} on {2}" -f $result.Name, $result.Status, $result.PSComputerName | Trace-Output -Level:Verbose
            }
        }

        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-SlbManagerConnectionToMux {
    <#
    .SYNOPSIS
        Validates the TCP connection between LoadBalancerMuxes and primary replica of SlbManager service within Network Controller.
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate
    )

    $ncRestParams = @{
        NcUri = $SdnEnvironmentObject.NcUrl
    }
    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $ncRestParams.Add('NcRestCredential', $NcRestCredential)
        }
    }

    $sdnHealthObject = [SdnHealth]::new()
    $array = @()

    $netConnectionExistsScriptBlock = {
        $tcpConnection = Get-NetTCPConnection -LocalPort 8560 -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Established" }
        if ($tcpConnection) {
            return $true
        }
    }

    try {
        "Validating connectivity between LoadBalancerMuxes and primary replica of SlbManager service within Network Controller" | Trace-Output
        $loadBalancerMux = Get-SdnLoadBalancerMux @ncRestParams

        # if no load balancer muxes configured within the environment, return back the health object to caller
        if ($null -ieq $loadBalancerMux) {
            return $sdnHealthObject
        }

        # get the current primary replica of Network Controller
        # if we cannot return the primary replica, then something is critically wrong with Network Controller
        # in which case we should mark this test as failed and return back to the caller with guidance to fix the SlbManagerService
        $primaryReplicaNode = Get-SdnServiceFabricReplica -NetworkController $SdnEnvironmentObject.EnvironmentInfo.NetworkController[0] -ServiceTypeName 'SlbManagerService' -Credential $NcRestCredential -Primary
        if ($null -ieq $primaryReplicaNode) {
            "Unable to return primary replica of SlbManagerService" | Trace-Output -Level:Error
            $sdnHealthObject.Result = 'FAIL'
            $sdnHealthObject.Remediation = "Fix the primary replica of SlbManagerService within Network Controller."
            return $sdnHealthObject
        }

        # enumerate through the load balancer muxes in the environment and validate the TCP connection state
        # we expect the primary replica for SlbManager within Network Controller to have an active connection for DIP:VIP programming to the Muxes
        foreach ($mux in $loadBalancerMux) {
            $virtualServer = Get-SdnResource @ncRestParams -ResourceRef $mux.properties.virtualServer.resourceRef
            $virtualServerConnection = $virtualServer.properties.connections[0].managementAddresses
            $connectionExists = Invoke-PSRemoteCommand -ComputerName $virtualServerConnection -Credential $Credential -ScriptBlock $netConnectionExistsScriptBlock
            if (-NOT $connectionExists) {
                "{0} is not connected to SlbManager of Network Controller" -f $mux.resourceRef | Trace-Output -Level:Error
                $sdnHealthObject.Result = 'FAIL'
                $sdnHealthObject.Remediation += "Investigate and fix TCP connectivity or x509 authentication between $($primaryReplicaNode.ReplicaAddress) and $($mux.resourceRef)."

                $object = [PSCustomObject]@{
                    LoadBalancerMux = $mux.resourceRef
                    SlbManagerPrimaryReplica = $primaryReplicaNode.ReplicaAddress
                }

                $array += $object
            }
            else {
                "{0} is connected to {1}" -f $mux.resourceRef, $primaryReplicaNode.ReplicaAddress | Trace-Output -Level:Verbose
            }
        }

        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-VfpDuplicatePort {
    <#
    .SYNOPSIS
        Validate there are no ports within VFP layer that may have duplicate MAC addresses.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()
    $array = @()

    try {
        "Validate no duplicate MAC addresses for ports within Virtual Filtering Platform (VFP)" | Trace-Output

        $vfpPorts = Get-SdnVfpVmSwitchPort -ComputerName $SdnEnvironmentObject.ComputerName -Credential $Credential
        $duplicateObjects = $vfpPorts | Where-Object {$_.MACaddress -ne '00-00-00-00-00-00' -and $null -ne $_.MacAddress} | Group-Object -Property MacAddress | Where-Object {$_.Count -ge 2}
        if($duplicateObjects){
            $array += $duplicateObjects
            $sdnHealthObject.Result = 'FAIL'

            # since there can be multiple grouped objects, we need to enumerate each duplicate group
            foreach($obj in $duplicateObjects){
                $sdnHealthObject.Remediation += "Remove the duplicate MAC addresses for $($obj.Name) within VFP"

                "Located {0} VFP ports associated with {1}:`r`n`n{2}`r`n" -f $obj.Count, $obj.Name, `
                    ($obj.Group `
                    | Select-Object @{n="Portname";e={"`t$($_.Portname)"}} `
                    | Select-Object -ExpandProperty Portname `
                    | Out-String `
                ) | Trace-Output -Level:Error
            }
        }

        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-VMNetAdapterDuplicateMacAddress {
    <#
    .SYNOPSIS
        Validate there are no adapters within hyper-v dataplane that may have duplicate MAC addresses.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()
    $array = @()

    try {
        "Validate no duplicate MAC addresses for network adapters within Hyper-V" | Trace-Output

        $vmNetAdapters = Get-SdnVMNetworkAdapter -ComputerName $SdnEnvironmentObject.ComputerName -AsJob -PassThru -Timeout 900 -Credential $Credential
        $duplicateObjects = $vmNetAdapters | Group-Object -Property MacAddress | Where-Object {$_.Count -ge 2}
        if($duplicateObjects){
            $array += $duplicateObjects
            $sdnHealthObject.Result = 'FAIL'

            # since there can be multiple grouped objects, we need to enumerate each duplicate group
            foreach($obj in $duplicateObjects){
                $sdnHealthObject.Remediation += "Remove the duplicate MAC addresses for $($obj.Name) within Hyper-V"
                "Located {0} virtual machines associated with MAC address {1}:`r`n`n{2}`r`n" -f $obj.Count, $obj.Name, `
                    ($obj.Group `
                    | Select-Object @{n="VMName";e={"`t$($_.VMName)"}} `
                    | Select-Object -ExpandProperty VMName `
                    | Out-String `
                ) | Trace-Output -Level:Error
            }
        }

        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Write-HealthValidationInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$Role,

        [Parameter(Mandatory = $true)]
        [String]$Name,

        [Parameter(Mandatory = $false)]
        [String[]]$Remediation
    )

    $details = Get-HealthData -Property 'HealthValidations' -Id $Name

    $outputString = "[$Role] $Name"
    $outputString += "`r`n`r`n"
    $outputString += "--------------------------`r`n"
    $outputString += "Description:`t$($details.Description)`r`n"
    $outputString += "Impact:`t`t$($details.Impact)`r`n"

    if (-NOT [string]::IsNullOrEmpty($Remediation)) {
        $outputString += "Remediation:`r`n`t -`t$($Remediation -join "`r`n`t -`t")`r`n"
    }

    if (-NOT [string]::IsNullOrEmpty($details.PublicDocUrl)) {
        $outputString += "`r`n"
        $outputString += "Additional information can be found at $($details.PublicDocUrl).`r`n"
    }

    $outputString += "`r`n--------------------------`r`n"
    $outputString += "`r`n"

    $outputString | Write-Host -ForegroundColor Yellow
}

function Debug-SdnFabricInfrastructure {
    <#
    .SYNOPSIS
        Executes a series of fabric validation tests to validate the state and health of the underlying components within the SDN fabric.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Role
        The specific SDN role(s) to perform tests and validations for. If ommitted, defaults to all roles.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    .EXAMPLE
        PS> Debug-SdnFabricInfrastructure
    .EXAMPLE
        PS> Debug-SdnFabricInfrastructure -NetworkController 'NC01' -Credential (Get-Credential) -NcRestCredential (Get-Credential)
    #>

    [CmdletBinding(DefaultParameterSetName = 'Role')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ComputerName')]
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [ValidateSet('Gateway', 'NetworkController', 'Server', 'LoadBalancerMux')]
        [String[]]$Role = ('Gateway','LoadBalancerMux','NetworkController','Server'),

        [Parameter(Mandatory = $true, ParameterSetName = 'ComputerName')]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ComputerName')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ComputerName')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ComputerName')]
        [X509Certificate]$NcRestCertificate
    )

    if ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType -ine 'ServiceFabric') {
        throw New-Object System.NotSupportedException("This function is only supported on Service Fabric clusters.")
    }

    $script:SdnDiagnostics_Health.Cache = $null
    $aggregateHealthReport = @()
    if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
        Confirm-IsNetworkController
    }

    if ($PSBoundParameters.ContainsKey('NcRestCertificate')) {
        $restCredParam = @{ NcRestCertificate = $NcRestCertificate }
    }
    else {
        $restCredParam = @{ NcRestCredential = $NcRestCredential }
    }

    $environmentInfo = Get-SdnInfrastructureInfo -NetworkController $NetworkController -Credential $Credential @restCredParam
    if($null -eq $environmentInfo){
        throw New-Object System.NullReferenceException("Unable to retrieve environment details")
    }

    try {
        # if we opted to specify the ComputerName rather than Role, we need to determine which role
        # the computer names are associated with
        if ($PSCmdlet.ParameterSetName -ieq 'ComputerName') {
            $Role = @()
            $ComputerName | ForEach-Object {
                $computerRole = $_ | Get-SdnRole -EnvironmentInfo $environmentInfo
                if ($computerRole) {
                    $Role += $computerRole
                }
            }
        }

        $Role = $Role | Sort-Object -Unique
        foreach ($object in $Role) {
            "Processing tests for {0} role" -f $object.ToString() | Trace-Output -Level:Verbose
            $config = Get-SdnModuleConfiguration -Role $object.ToString()

            $roleHealthReport = [SdnFabricHealthReport]@{
                Role = $object.ToString()
            }

            $sdnFabricDetails = [SdnFabricEnvObject]@{
                NcUrl = $environmentInfo.NcUrl
                Role  = $config
                EnvironmentInfo = $environmentInfo
            }

            # check to see if we were provided a specific computer(s) to test against
            # otherwise we will want to pick up the node name(s) from the environment info
            if ($ComputerName) {
                $sdnFabricDetails.ComputerName = $ComputerName
            }
            else {
                # in scenarios where there are not mux(es) or gateway(s) then we need to gracefully handle this
                # and move to the next role for processing
                if ($null -ieq $environmentInfo[$object.ToString()]) {
                    "Unable to locate fabric nodes for {0}. Skipping health tests." -f $object.ToString() | Trace-Output -Level:Warning
                    continue
                }

                $sdnFabricDetails.ComputerName = $environmentInfo[$object.ToString()]
            }

            $restApiParams = @{
                SdnEnvironmentObject    = $sdnFabricDetails
            }
            $restApiParams += $restCredParam

            $computerCredParams = @{
                SdnEnvironmentObject    = $sdnFabricDetails
                Credential              = $Credential
            }

            $computerCredAndRestApiParams = @{
                SdnEnvironmentObject    = $sdnFabricDetails
                Credential              = $Credential
            }
            $computerCredAndRestApiParams += $restCredParam

            # before proceeding with tests, ensure that the computer objects we are testing against are running the latest version of SdnDiagnostics
            Install-SdnDiagnostics -ComputerName $sdnFabricDetails.ComputerName -Credential $Credential

            # perform the health validations for the appropriate roles that were specified directly
            # or determined via which ComputerNames were defined
            switch ($object) {
                'Gateway' {
                    $roleHealthReport.HealthValidation += @(
                        Test-ResourceProvisioningState @restApiParams
                        Test-ResourceConfigurationState @restApiParams
                        Test-ServiceState @computerCredParams
                        Test-ScheduledTaskEnabled @computerCredParams
                    )
                }

                'LoadBalancerMux' {
                    $roleHealthReport.HealthValidation += @(
                        Test-ResourceProvisioningState @restApiParams
                        Test-ResourceConfigurationState @restApiParams
                        Test-ServiceState @computerCredParams
                        Test-ScheduledTaskEnabled @computerCredParams
                        Test-MuxBgpConnectionState @computerCredAndRestApiParams
                        Test-SlbManagerConnectionToMux @computerCredAndRestApiParams
                    )
                }

                'NetworkController' {
                    $roleHealthReport.HealthValidation += @(
                        Test-NcUrlNameResolution @computerCredAndRestApiParams
                        Test-ServiceState @computerCredParams
                        Test-ServiceFabricPartitionDatabaseSize @computerCredParams
                        Test-ServiceFabricClusterHealth @computerCredParams
                        Test-ServiceFabricApplicationHealth @computerCredParams
                        Test-ServiceFabricNodeStatus @computerCredParams
                        Test-NetworkInterfaceAPIDuplicateMacAddress @restApiParams
                        Test-ScheduledTaskEnabled @computerCredParams
                        Test-NetworkControllerCertCredential @computerCredAndRestApiParams
                    )
                }

                'Server' {
                    $roleHealthReport.HealthValidation += @(
                        Test-ResourceProvisioningState @restApiParams
                        Test-ResourceConfigurationState @restApiParams
                        Test-EncapOverhead @computerCredParams
                        Test-ProviderNetwork @computerCredParams
                        Test-ServiceState @computerCredParams
                        Test-ServerHostId @computerCredAndRestApiParams
                        Test-VfpDuplicatePort @computerCredParams
                        Test-VMNetAdapterDuplicateMacAddress @computerCredParams
                        Test-HostRootStoreNonRootCert @computerCredParams
                        Test-ScheduledTaskEnabled @computerCredParams
                        Test-NcHostAgentConnectionToApiService @computerCredAndRestApiParams
                    )
                }
            }

            # enumerate all the tests performed so we can determine if any completed with Warning or FAIL
            # if any of the tests completed with Warning, we will set the aggregate result to Warning
            # if any of the tests completed with FAIL, we will set the aggregate result to FAIL and then break out of the foreach loop
            # we will skip tests with PASS, as that is the default value
            foreach ($healthStatus in $roleHealthReport.HealthValidation) {
                if ($healthStatus.Result -eq 'Warning') {
                    $roleHealthReport.Result = $healthStatus.Result
                }
                elseif ($healthStatus.Result -eq 'FAIL') {
                    $roleHealthReport.Result = $healthStatus.Result
                    break
                }
            }

            # add the individual role health report to the aggregate report
            $aggregateHealthReport += $roleHealthReport
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
    finally {
        if ($aggregateHealthReport) {

            # enumerate all the roles that were tested so we can determine if any completed with Warning or FAIL
            $aggregateHealthReport | ForEach-Object {
                if ($_.Result -ine 'PASS') {
                    $role = $_.Role

                    # enumerate all the individual role tests performed so we can determine if any completed that are not PASS
                    $_.HealthValidation | ForEach-Object {
                        if ($_.Result -ine 'PASS') {
                            # add the remediation steps to an array list so we can pass it to the Write-HealthValidationInfo function
                            # otherwise if we pass it directly, it will be treated as a single string
                            $remediationList = [System.Collections.ArrayList]::new()
                            $_.Remediation | ForEach-Object { [void]$remediationList.Add($_)}

                            Write-HealthValidationInfo -Role $([string]$role) -Name $_.Name -Remediation $remediationList
                        }
                    }
                }
            }

            # save the aggregate health report to cache so we can use it for further analysis
            $script:SdnDiagnostics_Health.Cache = $aggregateHealthReport
        }
    }

    if ($script:SdnDiagnostics_Health.Cache) {
        "Results for fabric health have been saved to cache for further analysis. Use 'Get-SdnFabricInfrastructureResult' to examine the results." | Trace-Output
        return $script:SdnDiagnostics_Health.Cache
    }
}

function Get-SdnFabricInfrastructureResult {
    <#
        .SYNOPSIS
            Returns the results that have been saved to cache as part of running Debug-SdnFabricInfrastructure.
        .PARAMETER Role
            The name of the SDN role that you want to return test results from within the cache.
        .PARAMETER Name
            The name of the test results you want to examine.
        .EXAMPLE
            PS> Get-SdnFabricInfrastructureResult
        .EXAMPLE
            PS> Get-SdnFabricInfrastructureResult -Role Server
        .EXAMPLE
            PS> Get-SdnFabricInfrastructureResult -Role Server -Name 'Test-ServiceState'
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]$Role,

        [Parameter(Mandatory = $false)]
        [System.String]$Name
    )

    $cacheResults = $script:SdnDiagnostics_Health.Cache

    if ($PSBoundParameters.ContainsKey('Role')) {
        if ($cacheResults) {
            $cacheResults = $cacheResults | Where-Object {$_.Role -eq $Role}
        }
    }

    if ($PSBoundParameters.ContainsKey('Name')) {
        if ($cacheResults) {
            $cacheResults = $cacheResults.HealthValidation | Where-Object {$_.Name -eq $Name}
        }
    }

    return $cacheResults
}

