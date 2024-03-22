function Get-SdnOvsdbGlobalTable {
    <#
    .SYNOPSIS
        Gets the global table results from OVSDB.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnOvsdbGlobalTable -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Get-SdnOvsdbGlobalTable -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock { Get-SdnOvsdbGlobalTable } -Credential $Credential
        }
        else {
            Get-OvsdbGlobalTable
        }
    }
    catch {
        $_ | Trace-Exception
    }
}
