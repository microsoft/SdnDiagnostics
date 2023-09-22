function Debug-SdnVip {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [IPAddress]$VirtualIP,

        [Parameter(Mandatory = $false)]
        [System.String]$NetworkController = $(HostName),

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    $vip = @{
        Type = $null
        Properties = @{}
    }

    try {
        if (-NOT ($PSBoundParameters.ContainsKey('NetworkController'))) {
            $config = Get-SdnModuleConfiguration -Role 'NetworkController'
            $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
            if (-NOT ($confirmFeatures)) {
                "The current machine is not a NetworkController, run this on NetworkController or use -NetworkController parameter to specify one" | Trace-Output -Level:Warning
                return # don't throw exception, since this is a controlled scenario and we do not need stack exception tracing
            }
        }

        $environmentInfo = Get-SdnInfrastructureInfo -NetworkController $NetworkController -Credential $Credential -NcRestCredential $NcRestCredential
        if($null -eq $environmentInfo){
            throw New-Object System.NullReferenceException("Unable to retrieve environment details")
        }

        # L3 scenarios will see the ipConfiguration associated with a public IP Address resource
        # Load Balancer may have reference within the frontendIpConfigurations to a public IP Address resource or may be defined as private IP Address
        $publicIPAddresses = Get-SdnResource -NcUri $environmentInfo.NcUrl -Resource PublicIPAddresses -Credential $NcRestCredential
        $loadBalancers = Get-SdnResource -NcUri $environmentInfo.NcUrl -Resource LoadBalancers -Credential $NcRestCredential

        if ($publicIPAddresses) {
            $vipIP = $publicIPAddresses | Where-Object { $_.properties.ipAddress -eq $VirtualIP }
            if ($vipIP) {
                "Located {0} associated with {1}" -f $vipIP.resourceRef, $VirtualIP | Trace-Output

                $vip.Type = 'PublicIpAddress'
                $vip.Properties = $vipIP
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
