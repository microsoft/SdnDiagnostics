function Confirm-IpAddressInRange {
    <#
        .SYNOPSIS
            Uses .NET to compare the IpAddress specified to see if it falls within the StartAddress and EndAddress range specified.
        .PARAMETER IpAddress
            The IP Address that you want to validate.
        .PARAMETER StartAddress
            The lower end of the IP address range that you want to validate against.
        .PARAMETER EndAddress
            The upper end of the IP address range that you want to validate against.
        .EXAMPLE
            PS> Confirm-IpAddressInRange -IpAddress 192.168.0.10 -StartAddress 192.168.0.1 -EndAddress 192.168.0.255
    #>

    param(
        [System.String]$IpAddress,
        [System.String]$StartAddress,
        [System.String]$EndAddress
    )

    # if null ip address is specified, will default to $false that does not exist within range specified
    if([String]::IsNullOrEmpty($IpAddress)) {
        return $false
    }

    $ip = [System.Net.IPAddress]::Parse($IpAddress).GetAddressBytes()
    [array]::Reverse($ip)
    $ip = [System.BitConverter]::ToUInt32($ip, 0)

    $from = [System.Net.IPAddress]::Parse($StartAddress).GetAddressBytes()
    [array]::Reverse($from)
    $from = [System.BitConverter]::ToUInt32($from, 0)

    $to = [System.Net.IPAddress]::Parse($EndAddress).GetAddressBytes()
    [array]::Reverse($to)
    $to = [System.BitConverter]::ToUInt32($to, 0)

    $from -le $ip -and $ip -le $to
}
