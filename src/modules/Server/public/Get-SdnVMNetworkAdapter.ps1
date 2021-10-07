# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnVMNetworkAdapter {
    <#
    .SYNOPSIS
        Retrieves the virtual machine network adapters that are allocated on a hyper-v host
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers. To specify the local computer, type the computer name, localhost, or a dot (.). When the computer is in a different domain than the user, the fully qualified domain name is required
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER AsJob
        Switch indicating to trigger a background job to perform the operation.
    .PARAMETER PassThru
        Switch indicating to wait for background job completes and display results to current session.
    .PARAMETER Timeout
        Specify the timeout duration to wait before job is automatically terminated. If omitted, defaults to 600 seconds.
    .EXAMPLE
        PS> Get-SdnVMNetworkAdapter -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Get-SdnVMNetworkAdapter -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnVMNetworkAdapter -ComputerName 'Server01','Server02' -AsJob
    .EXAMPLE
        PS> Get-SdnVMNetworkAdapter -ComputerName 'Server01','Server02' -AsJob -PassThru
    .EXAMPLE
        PS> Get-SdnVMNetworkAdapter -ComputerName 'Server01','Server02' -AsJob -PassThru -Timeout 600
    #>

    param (
        [Parameter(Mandatory = $true)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [VMState]$VmState = 'Running',

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$AsJob,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$PassThru,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [int]$Timeout = 600
    )

    try {
        $scriptBlock = {
            $virtualMachines = Get-VM | Where-Object { $_.State -eq [String]$using:VmState }
            $virtualMachines | Get-VMNetworkAdapter
        }

        Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential `
            -AsJob:($AsJob.IsPresent) -PassThru:($PassThru.IsPresent) -ExecutionTimeout $Timeout
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
