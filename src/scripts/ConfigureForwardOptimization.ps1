<#
.SYNOPSIS
    Configures network adapter settings for optimal forwarding performance.
.DESCRIPTION
    This script sets the Receive Buffer Size, Send Buffer Size, and enables Forwarding Optimization
    on the specified network interface card (NIC) to enhance network performance.
.PARAMETER AdapterName
    The name of the network interface card to configure.
.PARAMETER NoRestart
    If specified, the network adapter will not be restarted after applying the settings. Changes may require a manual restart or system reboot to take effect.
.EXAMPLE
    PS> .\ConfigureForwardOptimization.ps1 -AdapterName "Ethernet"
    Configures the specified NIC with optimal forwarding settings and restarts the adapter to apply changes.
.EXAMPLE
    PS> .\ConfigureForwardOptimization.ps1 -AdapterName "Ethernet" -NoRestart
    Configures the specified NIC with optimal forwarding settings without restarting the adapter. A manual restart or system reboot may be required for changes to take effect.
#>

[CmdletBinding()]
param(
    [string]$AdapterName,

    [switch]$NoRestart
)

try {
    Get-NetAdapter -Name $AdapterName -ErrorAction Stop # Verify adapter exists first

    Write-Verbose "Configuring forwarding optimization settings on NIC: $AdapterName"
    if ($NoRestart) {
        Write-Information -MessageData "NoRestart switch is set. You may need to restart the adapter manually or reboot the computer for changes to take effect." -InformationAction Continue
    }
    else {
        Write-Warning "NoRestart switch is not set. The network adapter will be restarted automatically to apply changes which may temporarily disrupt network connectivity."
    }

    Set-NetAdapterAdvancedProperty -Name $AdapterName -DisplayName "Receive Buffer Size" -DisplayValue 16MB -NoRestart:$NoRestart
    Set-NetAdapterAdvancedProperty -Name $AdapterName -DisplayName "Send Buffer Size" -DisplayValue 32MB -NoRestart:$NoRestart
    Set-NetAdapterAdvancedProperty -Name $AdapterName -DisplayName "Forwarding Optimization" -DisplayValue Enabled -NoRestart:$NoRestart
}
catch {
    Write-Error "Failed to configure forwarding optimization on NIC: $AdapterName. Error: $_"
}