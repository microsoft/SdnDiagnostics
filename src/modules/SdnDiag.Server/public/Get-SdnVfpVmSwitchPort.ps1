function Get-SdnVfpVmSwitchPort {
    <#
    .SYNOPSIS
        Returns a list of ports from within virtual filtering platform.
    .PARAMETER PortName
        The port name of the VFP interface
    .PARAMETER VMName
        The Name of the Virtual Machine
    .PARAMETER VMID
        The ID of the Virtual Machine
    .PARAMETER MacAddress
        The MacAddress of the interface
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnVfpVmSwitchPort -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Get-SdnVfpVmSwitchPort -ComputerName 'RemoteComputer' -Credential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnVfpVmSwitchPort -VMName 'SDN-MUX01'
    .EXAMPLE
        PS> Get-SdnVfpVmSwitchPort -VMID 699FBDA2-15A0-4D73-A6EF-9D55623A27CE
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'Port')]
        [System.String]$PortName,

        [Parameter(Mandatory = $false, ParameterSetName = 'VMID')]
        [System.String]$VMID,

        [Parameter(Mandatory = $false, ParameterSetName = 'VMName')]
        [System.String]$VMName,

        [Parameter(Mandatory = $false, ParameterSetName = 'MacAddress')]
        [System.String]$MacAddress,

        [Parameter(Mandatory = $false, ParameterSetName = 'Port')]
        [Parameter(Mandatory = $false, ParameterSetName = 'VMID')]
        [Parameter(Mandatory = $false, ParameterSetName = 'VMName')]
        [Parameter(Mandatory = $false, ParameterSetName = 'MacAddress')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Port')]
        [Parameter(Mandatory = $false, ParameterSetName = 'VMID')]
        [Parameter(Mandatory = $false, ParameterSetName = 'VMName')]
        [Parameter(Mandatory = $false, ParameterSetName = 'MacAddress')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
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

        switch ($PSCmdlet.ParameterSetName) {
            'Port' { return ($results | Where-Object {$_.PortName -ieq $PortName}) }
            'VMID' { return ($results | Where-Object {$_.VMID -ieq $VMID}) }
            'VMName' { return ($results | Where-Object {$_.VMName -ieq $VMName}) }
            'MacAddress' {
                $MacAddress = Format-MacAddressWithDashes -MacAddress $MacAddress
                return ($results | Where-Object {$_.MacAddress -ieq $MacAddress})
            }

            default { return $results }
        }
    }
    catch {
       $_ | Trace-Output -Level:Error
    }
}
