# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-MuxDriverControl {
    if (-NOT (Get-Module -Name 'Microsoft.Cloudnet.Slb.Mux.MuxDriverControl')) {
        Import-Module 'C:\windows\System32\Microsoft.Cloudnet.Slb.Mux.MuxDriverControl.dll' -Force
    }

    return ([Microsoft.Cloudnet.Slb.Mux.Driver.SlbDriverControl]::new())
}

function Get-SdnMuxDistributedRouterIP {
    <#
        .SYNOPSIS
            This cmdlet returns the Distributed Router IPs that are advertised on the MUX.
        .PARAMETER VirtualIP
            The Virtual IP address (VIP) of the resource. If omitted, will return all VIPs programmed within the MUX driver.
        .EXAMPLE
            PS> Get-SdnMuxDistributedRouterIP
        .EXAMPLE
            PS> Get-SdnMuxDistributedRouterIP -VirtualIP 100.90.95.42
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$VirtualIP
    )

    try {
        $control = Get-MuxDriverControl

        $vipConfig = [System.Collections.Generic.List[Microsoft.Cloudnet.Slb.Mux.Driver.VipConfig]]::new()
        $control.GetDrips($null , [ref]$vipConfig)

        if ($VirtualIP) {
            return ($vipConfig | Where-Object {$_.AddressStr -ieq $VirtualIP})
        }
        else {
            return $vipConfig
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnMuxState {
    <#
        .SYNOPSIS
            This cmdlet retrieves the current state of the load balancer MUX.
    #>

    try {
        return (Get-MuxDriverControl)
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnMuxStatefulVip {
    <#
        .SYNOPSIS
            Gets details related to the stateful VIPs.
        .PARAMETER VirtualIP
            The Virtual IP address (VIP) of the resource. If omitted, will return all VIPs programmed within the MUX driver.
        .EXAMPLE
            PS> Get-SdnMuxStatefulVip
        .EXAMPLE
            PS> Get-SdnMuxStatefulVip -VirtualIP 100.90.95.42
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$VirtualIP
    )

    try {
        $control = Get-MuxDriverControl
        $statefulVips = [System.Collections.Generic.List[Microsoft.Cloudnet.Slb.Mux.Driver.VipEndpointKey]]::new()

        $control.GetStatefulVips($null, [ref]$statefulVips)

        if ($VirtualIP) {
            return ($statefulVips | Where-Object {$_.AddressStr -ieq $VirtualIP})
        }
        else {
            return $statefulVips
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnMuxStatelessVip {
    <#
        .SYNOPSIS
            Gets details related to the stateless VIPs.
        .PARAMETER VirtualIP
            The Virtual IP address (VIP) of the resource. If omitted, will return all VIPs programmed within the MUX driver.
        .EXAMPLE
            PS> Get-SdnMuxStatelessVip
        .EXAMPLE
            PS> Get-SdnMuxStatelessVip -VirtualIP 100.90.95.42
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$VirtualIP
    )

    try {
        $control = Get-MuxDriverControl
        $statelessVips = [System.Collections.Generic.List[Microsoft.Cloudnet.Slb.Mux.Driver.VipEndpointKey]]::new()

        $control.GetStatelessVips($null, [ref]$statelessVips)

        if ($VirtualIP) {
            return ($statelessVips | Where-Object {$_.AddressStr -ieq $VirtualIP})
        }
        else {
            return $statelessVips
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnMuxStats {
    <#
        .SYNOPSIS
            Get the statistics related to the Virtual IPs.
        .PARAMETER VirtualIP
            The Virtual IP address (VIP) of the resource. If omitted, will return all VIPs programmed within the MUX driver.
        .PARAMETER SkipReset
        .EXAMPLE
            PS> Get-SdnMuxStats
        .EXAMPLE
            PS> Get-SdnMuxStats -VirtualIP 100.90.95.42
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$VirtualIP,

        [Parameter(Mandatory = $false)]
        [System.Boolean]$SkipReset = $true
    )

    try {
        $control = Get-MuxDriverControl
        return ($control.GetGlobalStats($SkipReset))
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnMuxVip {
    <#
        .SYNOPSIS
            This cmdlet returns the VIP endpoint(s).
        .PARAMETER VirtualIP
            The Virtual IP address (VIP) of the resource. If omitted, will return all VIPs programmed within the MUX driver.
        .EXAMPLE
            PS> Get-SdnMuxVip
        .EXAMPLE
            PS> Get-SdnMuxVip -VirtualIP 100.90.95.42
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$VirtualIP
    )

    try {
        $control = Get-MuxDriverControl
        $vipConfig = [System.Collections.Generic.List[Microsoft.Cloudnet.Slb.Mux.Driver.VipConfig]]::new()

        $control.GetVips($null, [ref]$vipConfig)

        if ($VirtualIP) {
            return ($vipConfig | Where-Object {$_.AddressStr -ieq $VirtualIP})
        }
        else {
            return $vipConfig
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnMuxVipConfig {
    <#
        .SYNOPSIS
            Get configuration details such as the DIPs of the backend resources related to Virtual IP
        .PARAMETER VirtualIP
            The Virtual IP address (VIP) of the resource. If omitted, will return all VIPs programmed within the MUX driver.
        .EXAMPLE
            PS> Get-SdnMuxVipConfig
        .EXAMPLE
            PS> Get-SdnMuxVipConfig -VirtualIP 100.90.95.42
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$VirtualIP
    )

    try {
        $control = Get-MuxDriverControl
        $list = [System.Collections.Generic.List[Microsoft.Cloudnet.Slb.Mux.Driver.VipEndpointConfig]]::new()

        if ($VirtualIP) {
            $statefulVips = Get-SdnMuxStatefulVip -VirtualIp $VirtualIP
        }
        else {
            $statefulVips = Get-SdnMuxStatefulVip
        }

        foreach ($vip in $statefulVips) {
            $vipConfig = New-Object -Type Microsoft.Cloudnet.Slb.Mux.Driver.VipEndpointConfig
            $control.GetVipConfig($vip, [ref]$vipConfig)

            [void]$list.Add($vipConfig)
        }

        return $list
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnSlbMuxConfigurationState {
    <#
    .SYNOPSIS
        Outputs a set of configuration state files for the load balancer role.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .EXAMPLE
        PS> Get-SdnSlbMuxConfigurationState -OutputDirectory "C:\Temp\CSS_SDN"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    $ProgressPreference = 'SilentlyContinue'

    try {
        $config = Get-SdnRoleConfiguration -Role:LoadBalancerMux
        [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath "ConfigState"
        [System.IO.FileInfo]$regDir = Join-Path -Path $OutputDirectory.FullName -ChildPath "Registry"

        "Collect configuration state details for role {0}" -f $config.Name | Trace-Output

        if (-NOT (Initialize-DataCollection -Role:LoadBalancerMux -FilePath $OutputDirectory.FullName -MinimumMB 100)) {
            throw New-Object System.Exception("Unable to initialize environment for data collection")
        }

        # dump out the regkey properties
        Export-RegistryKeyConfigDetails -Path $config.properties.regKeyPaths -OutputDirectory $regDir.FullName

        # output slb configuration and states
        "Getting MUX Driver Control configuration settings" | Trace-Output -Level:Verbose
        Get-SdnMuxState | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnMuxState' -FileType json
        Get-SdnMuxDistributedRouterIP | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnMuxDistributedRouterIP' -FileType json
        Get-SdnMuxStatefulVip | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnMuxStatefulVip' -FileType json
        Get-SdnMuxStatelessVip | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnMuxStatelessVip' -FileType json
        Get-SdnMuxStats | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnMuxStats' -FileType json
        Get-SdnMuxVip | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnMuxVip' -FileType json
        Get-SdnMuxVipConfig | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnMuxVipConfig' -FileType json

        Get-GeneralConfigurationState -OutputDirectory $OutputDirectory.FullName
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }

    $ProgressPreference = 'Continue'
}

