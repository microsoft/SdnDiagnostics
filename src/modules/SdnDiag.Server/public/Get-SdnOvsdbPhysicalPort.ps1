function Get-SdnOvsdbPhysicalPort {
    <#
    .SYNOPSIS
        Gets the physical port table results from OVSDB MS_VTEP database.
    .PARAMETER PortId
        The port ID of the physical port to return.
    .PARAMETER InstanceId
        The instance ID of the physical port to return. This is the InstanceID of the port associated with networkInterface from Network Controller.
    .PARAMETER VMName
        The name of the virtual machine to return the physical port(s) for.
    .PARAMETER MacAddress
        The MAC address of the network interface to return the physical port(s) for.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnOvsdbPhysicalPort -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Get-SdnOvsdbPhysicalPort -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'PortId')]
        [GUID]$PortId,

        [Parameter(Mandatory = $false, ParameterSetName = 'InstanceId')]
        [GUID]$InstanceId,

        [Parameter(Mandatory = $false, ParameterSetName = 'VMName')]
        [System.String]$VMName,

        [Parameter(Mandatory = $false, ParameterSetName = 'MacAddress')]
        [System.String]$MacAddress,

        [Parameter(Mandatory = $false, ParameterSetName = 'PortId')]
        [Parameter(Mandatory = $false, ParameterSetName = 'InstanceId')]
        [Parameter(Mandatory = $false, ParameterSetName = 'VMName')]
        [Parameter(Mandatory = $false, ParameterSetName = 'MacAddress')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false, ParameterSetName = 'PortId')]
        [Parameter(Mandatory = $false, ParameterSetName = 'InstanceId')]
        [Parameter(Mandatory = $false, ParameterSetName = 'VMName')]
        [Parameter(Mandatory = $false, ParameterSetName = 'MacAddress')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            $result = Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock { Get-SdnOvsdbPhysicalPort } -Credential $Credential
        }
        else {
            $result = Get-OvsdbPhysicalPortTable
        }

        # once we have the results, filter based on the parameter set
        switch ($PSCmdlet.ParameterSetName) {
            'PortId' { return ($result | Where-Object { $_.vm_nic_port_id -eq $PortId }) }
            'InstanceId' { return ($result | Where-Object { $_.name -eq $InstanceId }) }
            'VMName' { return ($result | Where-Object { $_.vm_nic_vm_name -eq $VMName }) }
            'MacAddress' {
                $macAddresswithDashes = Format-MacAddressWithDashes -MacAddress $MacAddress
                $macAddressnoDashes = Format-MacAddressNoDashes -MacAddress $MacAddress
                return ($result | Where-Object { $_.vm_nic_macaddress -eq $macAddresswithDashes -or $_.vm_nic_macaddress -eq $macAddressnoDashes })
            }
            default { return $result }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
