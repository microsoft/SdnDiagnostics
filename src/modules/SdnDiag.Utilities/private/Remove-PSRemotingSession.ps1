function Remove-PSRemotingSession {
    <#
    .SYNOPSIS
        Gracefully removes any existing PSSessions
    .PARAMETER ComputerName
        The computer name(s) that should have any existing PSSessions removed
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String[]]$ComputerName
    )

    try {
        [int]$timeOut = 120
        $stopWatch =  [System.Diagnostics.Stopwatch]::StartNew()

        $sessions = Get-PSSession -Name "SdnDiag-*" | Where-Object {$_.ComputerName -iin $ComputerName}
        while($sessions){
            if($stopWatch.Elapsed.TotalSeconds -gt $timeOut){
                throw New-Object System.TimeoutException("Unable to drain PSSessions")
            }

            foreach($session in $sessions){
                if($session.Availability -ieq 'Busy'){
                    "{0} is currently {1}. Waiting for PSSession.. {2} seconds" -f $session.Name, $session.Availability, $stopWatch.Elapsed.TotalSeconds | Trace-Output
                    Start-Sleep -Seconds 5
                    continue
                }
                else {
                    "Removing PSSession {0}" -f $session.Name | Trace-Output -Level:Verbose
                    $session | Remove-PSSession -ErrorAction Continue
                }
            }

            $sessions = Get-PSSession -Name "SdnDiag-*" | Where-Object {$_.ComputerName -iin $ComputerName}
        }

        $stopWatch.Stop()
        "Successfully drained PSSessions for {0}" -f ($ComputerName -join ', ') | Trace-Output
    }
    catch {
        $stopWatch.Stop()
        $_ | Trace-Output -Level:Error
    }
}
