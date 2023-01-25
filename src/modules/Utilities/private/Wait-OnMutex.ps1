function Wait-OnMutex {
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$MutexId
    )

    try {
        $MutexInstance = New-Object System.Threading.Mutex($false, $MutexId)
        if ($MutexInstance.WaitOne(3000)) {
            return $MutexInstance
        }
        else {
            throw New-Object -TypeName System.TimeoutException("Failed to acquire Mutex")
        }
    }

    catch [System.Threading.AbandonedMutexException] {
        $MutexInstance = New-Object System.Threading.Mutex($false, $MutexId)
        return (Wait-OnMutex -MutexId $MutexId)
    }
    catch {
        $MutexInstance.ReleaseMutex()
        $_ | Write-Error
    }
}
