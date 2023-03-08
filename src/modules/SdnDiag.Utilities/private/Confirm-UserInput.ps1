function Confirm-UserInput {
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true)]
        [System.String]$Message = "Do you want to continue with this operation? [Y/N]: ",
        [System.String]$BackgroundColor = "Black",
        [System.String]$ForegroundColor = "Yellow"
    )

    $Message | Trace-Output -Level:Verbose
    Write-Host -ForegroundColor:$ForegroundColor -BackgroundColor:$BackgroundColor -NoNewline $Message
    $answer = Read-Host
    if ($answer) {
        $answer | Trace-Output -Level:Verbose
    }
    else {
        "User pressed enter key" | Trace-Output -Level:Verbose
    }

    return ($answer -ieq 'y')
}
