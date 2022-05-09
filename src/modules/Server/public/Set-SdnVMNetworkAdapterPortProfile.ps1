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
    .EXAMPLE
        Set-SdnVMNetworkAdapterPortProfile -VMName 'TestVM01' -MacAddress 001DD826100E
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [System.String]$VMName,

        [Parameter(Mandatory = $true)]
        [System.String]$MacAddress,

        [Parameter(Mandatory = $false)]
        [System.String]$HyperVHost,

        [Parameter(Mandatory = $true)]
        [System.Guid]$ProfileId,

        [Parameter(Mandatory = $false)]
        [System.Int16]$ProfileData = 1
    )

    try {
        if ($PSBoundParameters.ContainsKey('HyperVHost')) {
            Invoke-PSRemoteCommand -ComputerName $HyperVHost -ScriptBlock {
                Set-VMNetworkAdapterPortProfile -VMName $using:VMName -MacAddress $using:MacAddress -ProfileId $using:ProfileId -ProfileData $using:ProfileData
            }
        }
        else {
            Set-VMNetworkAdapterPortProfile -VMName $VMName -MacAddress $MacAddress -ProfileId $ProfileId -ProfileData $ProfileData
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
