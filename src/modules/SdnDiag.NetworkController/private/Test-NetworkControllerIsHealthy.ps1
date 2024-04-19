function Test-NetworkControllerIsHealthy {
    try {
        $null = Get-NetworkController -ErrorAction 'Stop'
        return $true
    }
    catch {
        return $false
    }
}
