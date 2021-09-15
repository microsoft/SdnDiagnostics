function Confirm-UserInput {
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true)]
        [System.String]$Message = "Do you want to continue with this operation? (y/n)",
        [System.String]$BackgroundColor = "Black",
        [System.String]$ForegroundColor = "Yellow"
    )

    $Message | Trace-Output -Level:Verbose
    Write-Host -ForegroundColor:$ForegroundColor -BackgroundColor:$BackgroundColor -NoNewline $Message  
    $answer = Read-Host

    return ($answer -ieq 'y')
}