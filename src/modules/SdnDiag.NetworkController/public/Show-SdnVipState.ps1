function Show-SdnVipState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [IPAddress]$VirtualIPAddress,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [Switch]$Detailed
    )

    try {
        if ($PSSenderInfo) {
            if ($Credential -eq [System.Management.Automation.PSCredential]::Empty -or $null -eq $Credential) {
                throw New-Object System.NotSupportedException("This operation is not supported in a remote session without supplying -Credential.")
            }
        }

        $slbManager = Connect-SlbManager -Credential $Credential -ErrorAction Stop
        if ($slbManager) {
            $consolidatedVipState = $slbManager.GetConsolidatedVipState($VirtualIPAddress, $Detailed)
            return $consolidatedVipState
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
