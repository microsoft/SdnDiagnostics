function Confirm-ProvisioningStateSucceeded {
    <#
    .SYNOPSIS
        Used to verify the resource within the NC NB API is succeeded
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Uri]$Uri,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential,

        [Parameter(Mandatory = $false)]
        [Switch]$DisableKeepAlive,

        [Parameter(Mandatory = $false)]
        [Switch]$UseBasicParsing,

        [Parameter(Mandatory = $false)]
        [Int]$TimeoutInSec = 120
    )

    $splat = @{
        Uri = $Uri
        Credential = $Credential
        DisableKeepAlive = $DisableKeepAlive
        UseBasicParsing = $UseBasicParsing
    }

    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        if ($stopWatch.Elapsed.TotalSeconds -gt $TimeoutInSec) {
            $stopWatch.Stop()

            return $false
        }

        $result = Invoke-RestMethodWithRetry @Splat
        if ($result.properties.provisioningState -ieq 'Succeeded') {
            $stopWatch.Stop()

            return $true
        }

        Start-Sleep -Seconds 5
    }
}
