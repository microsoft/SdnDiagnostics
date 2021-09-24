# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnOvsdbGlobalTable {
    <#
    .SYNOPSIS
        Gets the global table results from OVSDB.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers. 
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER AsJob
        Switch indicating to trigger a background job to perform the operation.
    .PARAMETER PassThru
        Switch indicating to wait for background job completes and display results to current session.
    .PARAMETER Timeout
        Specify the timeout duration to wait before job is automatically terminated. If omitted, defaults to 300 seconds.
    .EXAMPLE
        PS> Get-SdnOvsdbGlobalTable -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Get-SdnOvsdbGlobalTable -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnOvsdbGlobalTable -ComputerName 'Server01','Server02' -AsJob
    .EXAMPLE
        PS> Get-SdnOvsdbGlobalTable -ComputerName 'Server01','Server02' -AsJob -PassThru
    .EXAMPLE
        PS> Get-SdnOvsdbGlobalTable -ComputerName 'Server01','Server02' -AsJob -PassThru -Timeout 600
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
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
        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock { Get-SdnOvsdbGlobalTable } -Credential $Credential `
                -AsJob:($AsJob.IsPresent) -PassThru:($PassThru.IsPresent) -ExecutionTimeout $Timeout
        }
        else {
            Get-OvsdbGlobalTable
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
