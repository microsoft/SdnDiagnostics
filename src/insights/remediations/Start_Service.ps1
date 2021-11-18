param (
    [System.String]$Name
)

[System.Int32]$maxRetries = 3
[System.Int32]$i = 0

while ($i -lt $maxRetries) {
    $i++

    "Attempting to start service {0} [Attempt {1} of {2}]" -f $Name, $i, $maxRetries | Trace-Output
    $serviceState = Start-Service -Name $Name -PassThru -ErrorAction Continue

    "{0} is {1}" -f $Name, $serviceState.Status | Trace-Output
    if ($serviceState.Status -ieq 'Running') {
        return $true
    }
}

return $false

