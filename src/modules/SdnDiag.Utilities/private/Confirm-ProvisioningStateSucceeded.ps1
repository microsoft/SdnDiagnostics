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
        Uri              = $Uri
        Credential       = $Credential
        DisableKeepAlive = $DisableKeepAlive
        UseBasicParsing  = $UseBasicParsing
        Method           = 'Get'
        ErrorAction      = 'Stop'
    }

    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        if ($stopWatch.Elapsed.TotalSeconds -gt $TimeoutInSec) {
            $stopWatch.Stop()
            throw New-Object System.TimeoutException("ProvisioningState for $($result.resourceId) did not succeed within the alloted time")
        }

        $result = Invoke-RestMethodWithRetry @Splat
        switch ($result.properties.provisioningState) {
            'Updating' {
                "ProvisioningState for $($result.resourceId) is updating. Waiting for completion..." | Trace-Output
                Start-Sleep -Seconds 5
            }

            'Succeeded' {
                $stopWatch.Stop()

                "ProvisioningState for $($result.resourceId) succeeded." | Trace-Output
                return $true
            }

            'Failed' {
                $stopWatch.Stop()
                throw New-Object System.Exception("Failed to update $($result.resourceId). Examine Network Controller logs for more information.")
            }

            default {
                throw New-Object System.Exception("Unknown provisioning state $($result.properties.provisioningState)")
            }
        }
    }
}
