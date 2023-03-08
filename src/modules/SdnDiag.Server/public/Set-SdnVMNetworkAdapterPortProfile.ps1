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
        [System.Int16]$ProfileData = 1,

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
                    Set-VMNetworkAdapterPortProfile -VMName $using:VMName -MacAddress $using:MacAddress -ProfileId $using:ProfileId -ProfileData $using:ProfileData
                }
            }
            'Local' {
                Set-VMNetworkAdapterPortProfile -VMName $VMName -MacAddress $MacAddress -ProfileId $ProfileId -ProfileData $ProfileData
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
