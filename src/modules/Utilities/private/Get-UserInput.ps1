function Get-UserInput {
    <#
    .SYNOPSIS
        Used in scenarios where you need to prompt the user for input
    .PARAMETER Message
        The message that you want to display to the user
    .EXAMPLE
        $choice = Get-UserInput -Message "Do you want to proceed with operation? [Y/N]: "
        Switch($choice){
            'Y' {Do action}
            'N' {Do action}
            default {Do action}
        }
    #>

    param
    (
        [Parameter(Position = 0, ValueFromPipeline = $true)]
        [string]$Message,
        [string]$BackgroundColor = "Black",
        [string]$ForegroundColor = "Yellow"
    )

    Write-Host -ForegroundColor:$ForegroundColor -BackgroundColor:$BackgroundColor -NoNewline $Message;
    return Read-Host
}
