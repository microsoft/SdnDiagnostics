function Wait-OnMutex {
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$MutexId
    )

    try {
        $MutexInstance = New-Object System.Threading.Mutex($false, $MutexId)
        while (-NOT ($MutexInstance.WaitOne(1000))) {
            $totalWait++
            if ($totalWait -ge 10) {
                "System timeout acquiring Mutex" | Write-Warning
                return $null
            }

            Start-Sleep -Milliseconds 100
        }

        return $MutexInstance
    }

    catch [System.Threading.AbandonedMutexException] {
        $MutexInstance = New-Object System.Threading.Mutex($false, $MutexId)
        return Wait-OnMutex -MutexId $MutexId
    }
    catch {
        $MutexInstance.ReleaseMutex()
        $_ | Write-Error
    }
}
