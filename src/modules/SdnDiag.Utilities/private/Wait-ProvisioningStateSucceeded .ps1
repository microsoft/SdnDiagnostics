function Wait-ProvisioningStateSucceeded  {
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

    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
    $splat = @{
        Uri = $Uri
        Credential = $Credential
        DisableKeepAlive = $DisableKeepAlive
        UseBasicParsing = $UseBasicParsing
    }

    while ($true) {
        if ($stopWatch.Elapsed.TotalSeconds -gt $TimeoutInSec) {
            $stopWatch.Stop()

            throw New-Object System.TimeoutException("ProvisioningState for $($result.resourceId) did not succeed within the alloted time")
        }

        $result = Invoke-RestMethodWithRetry @splat
        "ProvisioningState: $($result.properties.provisioningState)" | Trace-Output -Level:Verbose

        switch ($result.properties.provisioningState) {
            'Updating' {
                Start-Sleep -Seconds 5
            }

            'Succeeded' {
                $stopWatch.Stop()
                return $true}

            'Failed' {
                $stopWatch.Stop()
                throw New-Object System.Exception("Failed to update $($result.resourceId)")
            }

            default {
                Start-Sleep -Seconds 5
            }
        }
    }
}
