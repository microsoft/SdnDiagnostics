function Test-Ping {
    <#
    .SYNOPSIS
        Sends ICMP echo request packets.
    .PARAMETER DestinationAddress
        Specifies the destination IP address to use.
    .PARAMETER SourceAddress
        Specifies the source IP address to use.
    .PARAMETER CompartmentId
        Specifies an ID of compartment to perform the ping from within.
    .PARAMETER BufferSize
        Specifies the size, in bytes, of the buffer sent with this command. The default value is 1472.
    .PARAMETER DontFragment
        This parameter sets the Don't Fragment flag in the IP header. You can use this parameter with the BufferSize parameter to test the Path MTU size.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [IPAddress]$DestinationAddress,

        [Parameter(Mandatory = $true)]
        [IPAddress]$SourceAddress,

        [Parameter(Mandatory = $false)]
        [int]$CompartmentId = (Get-NetCompartment | Where-Object {$_.CompartmentDescription -ieq 'Default Compartment'}).CompartmentId,

        [Parameter()]
        [int[]]$BufferSize = 1472,

        [Parameter(Mandatory = $false)]
        [switch]$DontFragment
    )

    try {
        $arrayList = [System.Collections.ArrayList]::new()

        foreach($size in $BufferSize){
            $Global:LASTEXITCODE = 0
            if($DontFragment){
                $ping = ping $DestinationAddress.IPAddressToString -c $CompartmentId -l $size -S $SourceAddress.IPAddressToString -n 2-f
            }
            else {
                $ping = ping $DestinationAddress.IPAddressToString -c $CompartmentId -l $size -S $SourceAddress.IPAddressToString -n 2
            }
    
            if($LASTEXITCODE -ieq 0){
                $status = 'Success'
            }
            else {
                $status = 'Failure'
            }
    
            $result = [PSCustomObject]@{
                SourceAddress = $SourceAddress.IPAddressToString
                DestinationAddress = $DestinationAddress.IPAddressToString
                CompartmentId = $CompartmentId
                BufferSize = $size
                Status = $status
                Result = $ping
            }

            [void]$arrayList.Add($result)
        }

        return $arrayList
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
