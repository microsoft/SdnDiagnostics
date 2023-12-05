function Enable-SdnVipTrace {
    <#
    .SYNOPSIS
        Enables network tracing on the SDN fabric infrastructure related to the specified VIP address.
    .PARAMETER VirtualIP
        Specify the Virtual IP address that you want to enable SDN fabric tracing for.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    .PARAMETER OutputDirectory
        Optional. Specifies a specific path and folder in which to save the files.
    .PARAMETER MaxTraceSize
        Optional. Specifies the maximum size in MB for saved trace files. If unspecified, the default is 1536.
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [System.String]$VirtualIP,

        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [ValidateScript({
            if ($_.Scheme -ne "http" -and $_.Scheme -ne "https") {
                throw New-Object System.FormatException("Parameter is expected to be in http:// or https:// format.")
            }
            return $true
        })]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [System.String]$OutputDirectory = "$(Get-WorkingDirectory)\NetworkTraces",

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [int]$MaxTraceSize = 1536
    )

    $networkTraceNodes = @()
    Reset-SdnDiagTraceMapping

    try {
        # lets try and locate the resources associated with the public VIP address
        # the SdnPublicIpPoolUsageSummary is useful for this scenario, as it has the logic to scan both publicIpAddresses and loadBalancers
        # to locate the VIP IP we are looking for
        $publicIpAddressUsage = Get-SdnPublicIPPoolUsageSummary -NcUri $NcUri -NcRestCredential $NcRestCredential
        $publicIpResource = $publicIpAddressUsage | Where-Object {$_.IPAddress -ieq $VirtualIP}
        if ($null -ieq $publicIpResource) {
            throw "Unable to locate resources associated to $VirtualIP"
        }

        # get the load balancer muxes, as we will need to enable tracing on them
        $loadBalancerMuxes = Get-SdnLoadBalancerMux -NcUri $NcUri -Credential $NcRestCredential -ManagementAddressOnly
        $networkTraceNodes += $loadBalancerMuxes

        # we want to query the servers within the SDN fabric so we can get a list of the vfp switch ports across the hyper-v hosts
        # as we will use this reference to locate where the resources are located within the fabric
        $servers = Get-SdnServer -NcUri $NcUri -Credential $NcRestCredential -ManagementAddressOnly
        $Script:SdnDiagnostics_Common.Cache['VfpSwitchPorts'] = Get-SdnVfpVmSwitchPort -ComputerName $servers -Credential $Credential

        # determine the network interfaces associated with the public IP address
        $associatedResource = Get-SdnResource -NcUri $NcUri -Credential $NcRestCredential -ResourceRef $publicIpResource.AssociatedResource
        switch -Wildcard ($associatedResource.resourceRef) {
            "/loadBalancers/*" {
                "{0} is associated with load balancer {1}" -f $VirtualIP, $associatedResource.resourceRef | Trace-Output

                # depending on the environments, the associatedResource may come back as the parent load balancer object
                # or may be the frontend IP configuration object so in either situation, we should just split the resourceRef string and query to get the
                # parent load balancer object to ensure consistency
                $parentResource = "{0}/{1}" -f $associatedResource.resourceRef.Split('/')[1], $associatedResource.resourceRef.Split('/')[2]
                $loadBalancer = Get-SdnResource -NcUri $NcUri -Credential $NcRestCredential -ResourceRef $parentResource

                $ipConfigurations = $loadBalancer.properties.backendAddressPools.properties.backendIPConfigurations.resourceRef
            }
            "/networkInterfaces/*" {
                "{0} is associated with network interface {1}" -f $VirtualIP, $associatedResource.resourceRef | Trace-Output
                $ipConfigurations = $associatedResource.resourceRef
            }

            # public IP address(es) should only ever be associated to load balancer or network interface resources
            # except in the case for the gateway pool, which we would not expect in this scenario at this time
            default {
                throw "Unable to determine associated resource type"
            }
        }

        $ipConfigurations | ForEach-Object {
            $ipConfig = Get-SdnResource -NcUri $NcUri -Credential $NcRestCredential -ResourceRef $_ -ErrorAction Stop
            if ($null -ieq $ipConfig) {
                throw "Unable to locate resource for $($_)"
            }

            "Located associated resource {0} with DIP address {1}" -f $ipConfig.resourceRef, $ipconfig.properties.privateIPAddress | Trace-Output

            # we need the mac address of the network interface to locate the vfp switch port
            # since the ipConfiguration is a subobject of the network interface, we need to split the resourceRef to get the network interface resource
            # since we know the resourceRefs are defined as /networkInterfaces/{guid}/ipConfigurations/{guid}, we can split on the '/' and get the 3rd element
            $netInterface = Get-SdnResource -NcUri $NcUri -Credential $NcRestCredential -ResourceRef "/networkInterfaces/$($_.Split('/')[2])"
            $macAddress = Format-MacAddress -MacAddress $netInterface.properties.privateMacAddress -Dashes
            $vfpPort = $Script:SdnDiagnostics_Common.Cache['VfpSwitchPorts'] | Where-Object {$_.MacAddress -ieq $macAddress}
            if ($null -ieq $vfpPort) {
                throw "Unable to locate vfp switch port for $macAddress"
            }

            "Located vfp switch port {0} on {1}" -f $vfpPort.PortName, $vfpPort.PSComputerName | Trace-Output

            # once we have the information we need, we can update our internal cache mapping
            Add-SdnDiagTraceMapping `
                -MacAddress $vfpPort.MacAddress `
                -InfraHost $vfpPort.PSComputerName `
                -PortId $vfpPort.PortId `
                -PortName $vfpPort.Portname `
                -NicName $vfpPort.NICname `
                -VmName $vfpPort.VMname `
                -VmInternalId $vfpPort.VMID `
                -PrivateIpAddress $ipConfig.properties.privateIPAddress
        }

        # once we have identified all the nodes we will enable tracing on
        # add the server(s) to the list of nodes we will enable tracing on
        # as this will be used to disable tracing once we are done
        $networkTraceNodes += $Script:SdnDiagnostics_Common.Cache['TraceMapping'].Keys
        $networkTraceNodes = $networkTraceNodes | Select-Object -Unique

        # ensure that we have SdnDiagnostics installed to the nodes that we need to enable tracing for
        Install-SdnDiagnostics -ComputerName $networkTraceNodes -Credential $Credential

        "Network traces will be enabled on:`r`n`t - LoadBalancerMux: {0}`r`n`t - Server: {1}`r`n" `
        -f ($loadBalancerMuxes -join ', '), ($Script:SdnDiagnostics_Common.Cache['TraceMapping'].Keys -join ', ') | Trace-Output

        # enable tracing on the infastructure
        $traceInfo = @()
        $traceInfo += Start-SdnNetshTrace -ComputerName $loadBalancerMuxes -Role 'LoadBalancerMux' -Credential $Credential -OutputDirectory $OutputDirectory -MaxTraceSize $MaxTraceSize
        $traceInfo += Start-SdnNetshTrace -ComputerName $Script:SdnDiagnostics_Common.Cache['TraceMapping'].Keys -Role 'Server' -Credential $Credential -OutputDirectory $OutputDirectory -MaxTraceSize $MaxTraceSize

        "Tracing has been enabled on the SDN infrastructure nodes {0}" -f ($traceInfo.PSComputerName -join ', ') | Trace-Output
        # at this point, tracing should be enabled on the sdn fabric and we can wait for user input to disable
        # once we receive user input, we will disable tracing on the infrastructure node(s)
        $null = Get-UserInput -Message "`r`nPress any key to disable tracing..."
        $null = Stop-SdnNetshTrace -ComputerName $networkTraceNodes -Credential $Credential

        "Tracing has been disabled on the SDN infrastructure. Saving configuration details to {0}\{1}_TraceMapping.json" -f (Get-WorkingDirectory), $VirtualIP | Trace-Output
        $Script:SdnDiagnostics_Common.Cache['TraceMapping'] | Export-ObjectToFile -FilePath (Get-WorkingDirectory) -Prefix $VirtualIP -Name 'TraceMapping' -FileType json -Depth 3

        $traceFileInfo = @()
        foreach ($obj in $traceInfo) {
            $traceFileInfo += [PSCustomObject]@{
                ComputerName = $obj.PSComputerName
                FileName = $obj.FileName
            }
        }

        return $traceFileInfo
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
