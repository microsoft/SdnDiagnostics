# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnVfpVmSwitchPort {
    <#
    .SYNOPSIS
        Returns a list of ports from within virtual filtering platform.
    .PARAMETER PortName
        The port name of the VFP interface
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnVfpVmSwitchPort -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Get-SdnVfpVmSwitchPort -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    .EXAMPLE
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, Position = 1)]
        [System.String]$PortName,

        [Parameter(Mandatory = $false, Position = 2)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false, Position = 3)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            $results = Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -ScriptBlock { Get-SdnVfpVmSwitchPort }
        }
        else {
            $results = Get-VfpVMSwitchPort
        }

        if ($PortName) {
            return ($results | Where-Object {$_.PortName -ieq $PortName})
        }
        else {
            return $results
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
