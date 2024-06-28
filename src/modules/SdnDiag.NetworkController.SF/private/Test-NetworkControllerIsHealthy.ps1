function Test-NetworkControllerIsHealthy {
    try {
        $null = Get-NetworkController -ErrorAction 'Stop'
        return $true
    }
    catch {
        "Network Controller is not healthy" | Trace-Output -Level:Error
        return $false
    }
}
