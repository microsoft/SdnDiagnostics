function Format-ByteSize {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [double]$Bytes
    )

    $gb = [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "{0}", $Bytes / 1GB)
    $mb = [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "{0}", $Bytes / 1MB)

    return ([PSCustomObject]@{
        GB = $gb
        MB = $mb
    })
}
