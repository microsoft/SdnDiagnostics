function Format-ByteSize {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [double]$Bytes
    )

    return ([PSCustomObject]@{
        GB = "{0}" -f ($Bytes / 1GB)
        MB = "{0}" -f ($Bytes / 1MB)
    })
}
