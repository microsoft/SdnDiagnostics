function Remove-PSRemotingSession {
    <#
    .SYNOPSIS
        Gracefully removes any existing PSSessions
    .PARAMETER ComputerName
        The computer name(s) that should have any existing PSSessions removed
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String[]]$ComputerName
    )

    try {
        [int]$timeOut = 120
        $stopWatch =  [System.Diagnostics.Stopwatch]::StartNew()

        $sessions = Get-PSSession -Name "SdnDiag-*"
        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            $sessions | Where-Object {$_.ComputerName -iin $ComputerName}
        }

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
                    "Removing PSSession {0} for {1}" -f $session.Name, $session.ComputerName | Trace-Output

                    try {
                        $session | Remove-PSSession -ErrorAction Stop
                    }
                    catch {
                        "Unable to remove PSSession {0} for {1}. Error: {2}" -f $session.Name, $session.ComputerName, $_.Exception.Message | Trace-Output -Level:Warning
                        continue
                    }
                }
            }

            $sessions = Get-PSSession -Name "SdnDiag-*" | Where-Object {$_.ComputerName -iin $ComputerName}
        }

        $stopWatch.Stop()
    }
    catch {
        $stopWatch.Stop()
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
