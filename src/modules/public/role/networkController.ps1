function Get-SdnResource {
    <#
    .SYNOPSIS
        Invokes a web request to SDN API for the requested resource.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER ResourceRef
        The resource ref of the object you want to perform the operation against
    .PARAMETER ResourceType
        The resource type you want to perform the operation against
    .EXAMPLE
        Get-SdnResource -ResourceType PublicIPAddresses
    .EXAMPLE
        Get-SdnResource -NcUri "https://nc.$env:USERDNSDOMAIN" -ResourceRef "/publicIPAddresses/d9266251-a3ba-4ac5-859e-2c3a7c70352a"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $true, ParameterSetName = 'NoResourceRef')]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [System.String]$ResourceRef,

        [Parameter(Mandatory = $true, ParameterSetName = 'NoResourceRef')]
        [SdnApiResource]$ResourceType,

        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $false, ParameterSetName = 'NoResourceRef')]
        [System.String]$Version = 'v1',

        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $false, ParameterSetName = 'NoResourceRef')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {

        [System.String]$method = 'GET'

        if($PSBoundParameters.ContainsKey('ResourceRef')){
            [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri.AbsoluteUri -ApiVersion $Version -ResourceRef $ResourceRef
        }
        else {
            [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri.AbsoluteUri -ApiVersion $Version -ServiceName $ResourceType
        }

        "{0} {1}" -f $method, $uri | Trace-Output -Level:Verbose
        if($Credential -ne [System.Management.Automation.PSCredential]::Empty){
            $result = Invoke-RestMethod -Uri $uri -Method $method -UseBasicParsing -Credential $Credential -ErrorAction Stop
        }
        else {
            $result = Invoke-RestMethod -Uri $uri -Method $method -UseBasicParsing -UseDefaultCredentials -ErrorAction Stop
        }

        # if multiple objects are returned, they will be nested under a property called value
        # so we want to do some manual work here to ensure we have a consistent behavior on data returned back
        if($result.value){
            return $result.value
        }
        else {
            return $result
        }
    }
    catch {
        "{0}`nAbsoluteUri:{1}`n{2}" -f $_.Exception, $_.TargetObject.Address.AbsoluteUri, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnServers {
    <#
    .SYNOPSIS
        Returns a list of servers from network controller
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [switch]$ManagementAddressOnly,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $result = Get-SdnResource -NcUri $NcUri.AbsoluteUri -ResourceType:Servers -Credential $Credential

        foreach($obj in $result){
            if($obj.properties.provisioningState -ne 'Succeeded'){
                "{0} is reporting provisioningState: {1}" -f $obj.resourceId, $obj.properties.provisioningState | Trace-Output -Level:Warning
            }
        }

        if($ManagementAddressOnly){
            # there might be multiple connection endpoints to each node so we will want to only return the unique results
            # this does not handle if some duplicate connections are listed as IPAddress with another record saved as NetBIOS or FQDN
            # further processing may be required by the calling function to handle that
            return ($result.properties.connections.managementAddresses | Sort-Object -Unique)
        }
        else{
            return $result
        }
    } 
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnNetworkControllers {
    <#
    .SYNOPSIS
        Returns a list of servers from network controller
    .PARAMETER NetworkController
        One network conroller node name or ip address
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$NetworkController,

        [Parameter(Mandatory = $false)]
        [switch]$ServerNameOnly,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $result = Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock {Get-NetworkControllerNode} -Credential $Credential
        foreach($obj in $result){
            if($obj.Status -ine 'Up'){
                "{0} is reporting status {1}" -f $obj.Name, $obj.Status | Trace-Output -Level:Warning
            }
        }

        if($ServerNameOnly){
            return $result.Name
        }
        else{
            return $result
        }

    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnLoadBalancerMuxes {
    <#
    .SYNOPSIS
        Returns a list of load balancer muxes from network controller
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [switch]$ResourceIdOnly,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $result = Get-SdnResource -NcUri $NcUri.AbsoluteUri -ResourceType:LoadBalancerMuxes -Credential $Credential
        foreach($obj in $result){
            if($obj.properties.provisioningState -ne 'Succeeded'){
                "{0} is reporting provisioningState: {1}" -f $obj.resourceId, $obj.properties.provisioningState | Trace-Output -Level:Warning
            }
        }

        if($ResourceIdOnly){
            return $result.resourceId
        }
        else{
            return $result
        }
    } 
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnGateways {
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

        [Parameter(Mandatory = $false)]
        [switch]$ResourceIdOnly,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $result = Get-SdnResource -NcUri $NcUri.AbsoluteUri -ResourceType:Gateways -Credential $Credential
        foreach($obj in $result){
            if($obj.properties.provisioningState -ne 'Succeeded'){
                "{0} is reporting provisioningState: {1}" -f $obj.resourceId, $obj.properties.provisioningState | Trace-Output -Level:Warning
            }
        }

        if($ResourceIdOnly){
            return $result.resourceId
        }
        else{
            return $result
        }
    } 
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}


function Get-SdnInfrastructureInfo {
    <#
    .SYNOPSIS
        Get the SDN Infrastrucutre Info based on one NC VM. The function will update:
        - $Global:SdnDiagnostics.NcUrl
        - $Global:SdnDiagnostics.NC
        - $Global:SdnDiagnostics.MUX
        - $Global:SdnDiagnostics.Gateway
        - $Global:SdnDiagnostics.Host
    .PARAMETER NcVM
        Specifies one of the network controller VM name.
    .PARAMETER Credential
        The NC Admin Credential if different from current logon user credential.
    .PARAMETER NcRestCredential
        The NC Rest API credential if different from current logon user credential.    
        
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$NetworkController,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    try {

        if([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.NcUrl))
        {
            $result = Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock {Get-NetworkController} -Credential $Credential
            $Global:SdnDiagnostics.NcUrl = "https://$($result.RestName)"
        }
        
        if([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.NC))
        {
            $Global:SdnDiagnostics.NC = Get-SdnNetworkControllers -NetworkController $NetworkController -ServerNameOnly -Credential $Credential
        }

        if([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.MUX))
        {
            $Global:SdnDiagnostics.MUX = Get-SdnLoadBalancerMuxes -NcUri $($Global:SdnDiagnostics.NcUrl) -ResourceIdOnly -Credential $NcRestCredential
        }

        if([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.Gateway))
        {
            $Global:SdnDiagnostics.Gateway = Get-SdnGateways -NcUri $($Global:SdnDiagnostics.NcUrl) -ResourceIdOnly -Credential $NcRestCredential
        }

        if([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.Host))
        {
            #The credential for NC REST API could be different from NC Admin credential. Caller need to determine the credential to be used. 
            $Global:SdnDiagnostics.Host = Get-SdnServers -NcUri $($Global:SdnDiagnostics.NcUrl) -ManagementAddressOnly -Credential $NcRestCredential
        }


        $SdnInfraInfo = [PSCustomObject]@{
            RestName = $Global:SdnDiagnostics.NcUrl
            NC = $Global:SdnDiagnostics.NC
            MUX = $Global:SdnDiagnostics.MUX
            Gateway = $Global:SdnDiagnostics.Gateway
            Host = $Global:SdnDiagnostics.Host
        }

        return $SdnInfraInfo
    } 
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}