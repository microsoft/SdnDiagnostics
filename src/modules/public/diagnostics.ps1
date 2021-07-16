function Get-SdnOvsdbAddressMapping {
    <#
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$AsJob,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$PassThru,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [int]$Timeout = 300
    )

    try {
        Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock {Get-OvsdbAddressMapping} -Credential $Credential `
            -AsJob:($AsJob.IsPresent) -PassThru:($PassThru.IsPresent) -ExecutionTimeout $Timeout
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnOvsdbFirewallRuleTable {
    <#
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$AsJob,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$PassThru,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [int]$Timeout = 300
    )

    try {
        Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock {Get-OvsdbFirewallRuleTable} -Credential $Credential `
            -AsJob:($AsJob.IsPresent) -PassThru:($PassThru.IsPresent) -ExecutionTimeout $Timeout
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnOvsdbPhysicalPortTable {
    <#
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$AsJob,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$PassThru,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [int]$Timeout = 300
    )

    try {
        Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock {Get-OvsdbPhysicalPortTable} -Credential $Credential `
            -AsJob:($AsJob.IsPresent) -PassThru:($PassThru.IsPresent) -ExecutionTimeout $Timeout
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnOvsdbUcastMacRemoteTable {
    <#
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$AsJob,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$PassThru,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [int]$Timeout = 300
    )

    try {
        Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock {Get-OvsdbUcastMacRemoteTable} -Credential $Credential `
            -AsJob:($AsJob.IsPresent) -PassThru:($PassThru.IsPresent) -ExecutionTimeout $Timeout
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnOvsdbGlobalTable {
    <#
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$AsJob,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$PassThru,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [int]$Timeout = 300
    )

    try {
        Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock {Get-OvsdbGlobalTable} -Credential $Credential `
            -AsJob:($AsJob.IsPresent) -PassThru:($PassThru.IsPresent) -ExecutionTimeout $Timeout
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnVfpVmSwitchPorts {
    <#
    .SYNOPSIS
        Returns a list of ports from within VFP
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$AsJob,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$PassThru,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [int]$Timeout = 300
    )

    try {
        Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock {Get-VfpVmSwitchPorts} -Credential $Credential `
            -AsJob:($AsJob.IsPresent) -PassThru:($PassThru.IsPresent) -ExecutionTimeout $Timeout
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnProviderAddresses {
    <#
    .SYNOPSIS
        Retrieves the Provider Address that is assigned to the computer
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$AsJob,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$PassThru,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [int]$Timeout = 300
    )

    try {
        Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock {Get-ProviderAddress} -Credential $Credential `
            -AsJob:($AsJob.IsPresent) -PassThru:($PassThru.IsPresent) -ExecutionTimeout $Timeout
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnSlbStateInformation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [int]$ExecutionTimeOut = 900,
    
        [Parameter(Mandatory = $false)]
        [int]$PollingInterval = 5
    )

    try {
        [System.String]$uri = "{0}/networking/v1/diagnostics/slbstate" -f $NcUri.AbsoluteUri
        "Gathering SLB state information from {0}" -f $uri | Trace-Output -Level:Verbose

        $stopWatch =  [system.diagnostics.stopwatch]::StartNew()

        if($Credential -ne [System.Management.Automation.PSCredential]::Empty){
            $putResult = Invoke-WebRequest -Headers @{"Accept"="application/json"} `
                -Content "application/json; charset=UTF-8" `
                -Uri $uri `
                -Body "{}" `
                -Method PUT `
                -UseBasicParsing `
                -Credential $Credential
        }
        else {
            $putResult = Invoke-WebRequest -Headers @{"Accept"="application/json"} `
                -Content "application/json; charset=UTF-8" `
                -Uri $uri `
                -Body "{}" `
                -Method PUT `
                -UseBasicParsing `
                -UseDefaultCredentials
        }

        $resultObject = ConvertFrom-Json $putResult.Content
        $operationId = $resultObject.properties.operationId
        [System.String]$operationURI = "{0}/{1}" -f $uri, $operationId

        while($true){
            if($stopWatch.Elapsed.TotalSeconds -gt $ExecutionTimeOut){
                $msg = "Unable to get results for OperationId: {0}. Operation timed out" -f $operationId
                throw New-Object System.TimeoutException($msg)
            }

            Start-Sleep -Seconds $PollingInterval

            if($Credential){
                $stateResult = Invoke-WebRequest -Uri $operationURI `
                -Method Get `
                -UseBasicParsing `
                -Credential $Credential
            }
            else {
                $stateResult = Invoke-WebRequest -Uri $operationURI `
                -Method Get `
                -UseBasicParsing `
                -UseDefaultCredentials
            }

            if(($stateResult | ConvertFrom-Json).properties.provisioningState -ine 'Updating'){
                break
            }
        }

        $stopWatch.Stop()
        
        if($stateResult.properties.provisioningState -ine 'Succeeded'){
            $msg = "Unable to get results for OperationId: {0}. {1}" -f $operationId, $stateResult.properties
            throw New-Object System.Exception($msg)
        }
        else {
            return $stateResult.Content
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

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

function Get-SdnApiResources {
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
                Get-SdnResource -NcUri $NcUri.AbsoluteUri -ResourceRef $resource | Export-ObjectToFile -FilePath $outputDir.FullName -Name $resource.Replace('/','_') -FileType json
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

function Get-SdnNetworkControllerStateFiles {
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
        # once the operation completes and returns true, then enumerate through the ComputerNames defined to collect the files via WinRM
        $result = Start-SdnNcImosDump -NcUri $NcUri.AbsoluteUri -Credential $Credential -ExecutionTimeOut $ExecutionTimeOut
        if($result){
            foreach($obj in $ComputerName){
                $session = New-PSRemotingSession -ComputerName $obj -Credential $Credential
                if($session){
                    "Copying Network Controller State files {0} via WinRM" -f $session.ComputerName | Trace-Output
                    Copy-Item -FromSession $session -Path "$($config.properties.netControllerStatePath)\*" -Destination $outputDir.FullName -Force -Recurse
                }
            }
        }        
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-VMNetAdapters {
    <#
    .SYNOPSIS
        Retrieves the virtual machine network adapters that are allocated on a hyper-v host
    .PARAMETER ComputerName
        The computer name(s) that you want return VM adapters from
    .PARAMETER VmState
        The state of the virtual machine on the host. If ommitted, defaults to Running
    .EXAMPLE
        Get-VMNetAdapters -ComputerName (Get-SdnServers -ManagementAddressOnly)
    #>

    param (
        [Parameter(Mandatory = $true)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [Microsoft.HyperV.PowerShell.VMState]$VmState = 'Running',

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$AsJob,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$PassThru,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [int]$Timeout = 300
    )

    try {
        $scriptBlock = {
            $virtualMachines = Get-VM | Where-Object {$_.State -eq $using:VmState}
            $virtualMachines | Get-VMNetworkAdapter
        }

        Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential `
            -AsJob:($AsJob.IsPresent) -PassThru:($PassThru.IsPresent) -ExecutionTimeout $Timeout
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Debug-SdnFabricInfrastructure {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [ArgumentCompleter({
            $possibleValues = Get-ChildItem -Path "$PSScriptRoot\..\..\private\health" -Directory | Select-Object -ExpandProperty Name
            return $possibleValues | ForEach-Object { $_ }
        })]
        [System.String]$Role,

        [Parameter(Mandatory = $false)]
        [ArgumentCompleter({
            $possibleValues = Get-ChildItem -Path "$PSScriptRoot\..\..\private\health" -Recurse | Where-Object {$_.Extension -eq '.ps1'} | Select-Object -ExpandProperty BaseName
            return $possibleValues | ForEach-Object { $_ }
        })]
        [System.String]$ValidationTest
    )

    try {
        $Global:SdnDiagnostics.NcUrl = $NcUri.AbsoluteUri

        if($PSBoundParameters.ContainsKey('Role')){
            $healthValidationScripts = Get-ChildItem -Path "$PSScriptRoot\..\..\private\health\$Role" -Recurse | Where-Object {$_.Extension -eq '.ps1'}
        }
        elseif($PSBoundParameters.ContainsKey('ValidationTest')){
            $healthValidationScripts = Get-ChildItem -Path "$PSScriptRoot\..\..\private\health" -Recurse | Where-Object {$_.BaseName -ieq $ValidationTest}
            if($healthValidationScripts.Count -gt 1){
                throw New-Object System.Exception("Unexpected number of health validations returned")
            }
        }
        else {
            $healthValidationScripts = Get-ChildItem -Path "$PSScriptRoot\..\private\health" -Recurse | Where-Object {$_.Extension -eq '.ps1'}
        }

        if($null -eq $healthValidationScripts){
            throw New-Object System.NullReferenceException("No health validations returned")
        }

        foreach($script in $healthValidationScripts){
            # get the raw content of the script
            $code = Get-Content -Path $script.FullName -Raw

            # list all the functions in ps1 using language namespace parser
            $functionName = [Management.Automation.Language.Parser]::ParseInput($code, [ref]$null, [ref]$null).EndBlock.Statements.FindAll([Func[Management.Automation.Language.Ast,bool]]{$args[0] -is [Management.Automation.Language.FunctionDefinitionAst]}, $false) `
                | Select-Object -ExpandProperty Name
            
            # since there might be multiple functions in the script, we want to filter and only get the validation function
            $function = $functionName | Where-Object {$_ -like "Test-*"} | Select-Object -First 1
            
            # execute the function
            if($null -ne $function){
                Invoke-Expression -Command $function
            }
        }
    }
    catch{
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    } 
}
