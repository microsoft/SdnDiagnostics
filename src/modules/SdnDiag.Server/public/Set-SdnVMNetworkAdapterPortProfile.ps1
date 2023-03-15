function Set-SdnVMNetworkAdapterPortProfile {
    <#
    .SYNOPSIS
        Configures the port profile applied to the virtual machine network interfaces.
    .PARAMETER VMName
        Specifies the name of the virtual machine.
    .PARAMETER MacAddress
        Specifies the MAC address of the VM network adapter.
    .PARAMETER ProfileId
        The InstanceID of the Network Interface taken from Network Controller.
    .PARAMETER ProfileData
        1 = VfpEnabled, 2 = VfpDisabled (usually in the case of Mux). If ommited, defaults to 1.
    .PARAMETER HyperVHost
        Type the NetBIOS name, an IP address, or a fully qualified domain name of the computer that is hosting the virtual machine.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        Set-SdnVMNetworkAdapterPortProfile -VMName 'TestVM01' -MacAddress 001DD826100E
    #>

    [CmdletBinding(DefaultParameterSetName = 'Local')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Remote')]
        [System.String]$VMName,

        [Parameter(Mandatory = $true, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Remote')]
        [System.String]$MacAddress,

        [Parameter(Mandatory = $true, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Remote')]
        [System.Guid]$ProfileId,

        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [Int]$ProfileData = 1,

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.String]$HyperVHost,

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        switch ($PSCmdlet.ParameterSetName) {
            'Remote' {
                Invoke-PSRemoteCommand -ComputerName $HyperVHost -Credential $Credential -ScriptBlock {
                    param([Parameter(Position = 0)][String]$param1, [Parameter(Position = 1)][String]$param2, [Parameter(Position = 2)][Guid]$param3, [Parameter(Position = 3)][Int]$param4)
                    Set-VMNetworkAdapterPortProfile -VMName $param1 -MacAddress $param2 -ProfileId $param3 -ProfileData $param4
                } -ArgumentList $VMName, $MacAddress, $ProfileId, $ProfileData
            }
            'Local' {
                Set-VMNetworkAdapterPortProfile -VMName $VMName -MacAddress $MacAddress -ProfileId $ProfileId -ProfileData $ProfileData
            }
        }
    }
    catch {
        $_ | Trace-Exception
    }
}
