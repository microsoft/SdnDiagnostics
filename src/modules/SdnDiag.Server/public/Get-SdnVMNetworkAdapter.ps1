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

    [CmdletBinding(DefaultParameterSetName = 'Local')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [VMState]$VmState = 'Running',

        [Parameter(Mandatory = $false, ParametersetName = 'Remote')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [Switch]$AsJob,

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [Switch]$PassThru,

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [int]$Timeout = 600
    )

    try {
        if ($PSCmdlet.ParameterSetName -eq 'Local') {
            $virtualMachines = Get-VM | Where-Object { $_.State -eq $VmState.ToString() }
            return ($virtualMachines | Get-VMNetworkAdapter)
        }
        else {
            Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -ScriptBlock { Get-SdnVMNetworkAdapter } -ArgumentList @($VmState) `
            -AsJob:($AsJob.IsPresent) -PassThru:($PassThru.IsPresent) -ExecutionTimeout $Timeout
        }
    }
    catch {
       $_ | Trace-Output -Level:Error
    }
}
