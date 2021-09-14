function Get-SdnVMNetworkAdapter {
    <#
    .SYNOPSIS
        Retrieves the virtual machine network adapters that are allocated on a hyper-v host
    .PARAMETER ComputerName
        The computer name(s) that you want return VM adapters from
    .PARAMETER VmState
        The state of the virtual machine on the host. If ommitted, defaults to Running
    .EXAMPLE
        Get-SdnVMNetworkAdapter -ComputerName (Get-SdnServer -ManagementAddressOnly)
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
        [int]$Timeout = 300
    )

    try {
        $scriptBlock = {
            $virtualMachines = Get-VM | Where-Object { $_.State -eq $using:VmState }
            $virtualMachines | Get-VMNetworkAdapter
        }

        Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential `
            -AsJob:($AsJob.IsPresent) -PassThru:($PassThru.IsPresent) -ExecutionTimeout $Timeout
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
