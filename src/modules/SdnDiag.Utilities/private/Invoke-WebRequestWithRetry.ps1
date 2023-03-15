function Invoke-WebRequestWithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [System.Uri]$Uri,

        [Parameter(Mandatory = $false)]
        [Microsoft.PowerShell.Commands.WebRequestMethod]$Method = 'Get',

        [Parameter(Mandatory = $false)]
        [System.Collections.IDictionary]$Headers,

        [Parameter (Mandatory = $false)]
        [System.String]$ContentType,

        [Parameter(Mandatory = $false)]
        [System.Object] $Body,

        [Parameter(Mandatory = $false)]
        [Switch] $DisableKeepAlive,

        [Parameter(Mandatory = $false)]
        [Switch] $UseBasicParsing,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutInSec = 600,

        [Parameter(Mandatory = $false, ParameterSetName = 'Retry')]
        [Switch]$Retry,

        [Parameter(Mandatory = $false, ParameterSetName = 'Retry')]
        [Int]$MaxRetry = 3,

        [Parameter(Mandatory = $false, ParameterSetName = 'Retry')]
        [Int]$RetryIntervalInSeconds = 30
    )

    $params = @{
        'Headers'     = $Headers;
        'ContentType' = $ContentType;
        'Method'      = $Method;
        'Uri'         = $Uri;
        'TimeoutSec'  = $TimeoutInSec
    }

    if ($null -ne $Body) {
        $params.Add('Body', $Body)
    }

    if ($DisableKeepAlive.IsPresent) {
        $params.Add('DisableKeepAlive', $true)
    }

    if ($UseBasicParsing.IsPresent) {
        $params.Add('UseBasicParsing', $true)
    }

    if ($Credential -ne [System.Management.Automation.PSCredential]::Empty -and $null -ne $Credential) {
        $params.Add('Credential', $Credential)
    }
    else {
        $params.Add('UseDefaultCredentials', $true)
    }

    $counter = 0
    while ($true) {
        $counter++

        try {
            "Performing {0} request to uri {1}" -f $Method, $Uri | Trace-Output -Level:Verbose
            if ($Body) {
                "Body:`n`t{0}" -f $Body | Trace-Output -Level:Verbose
            }

            $result = Invoke-WebRequest @params

            break
        }
        catch {
            if ($_.Exception.Response.StatusCode -eq "NotFound") {
                "{0} ({1})" -f $_.Exception.Message, $_.Exception.Response.ResponseUri.AbsoluteUri | Trace-Output -Level:Warning
                return $null
            }
            else {
                $_ | Trace-Output -Level:Failure
            }

            if (($counter -le $MaxRetry) -and $Retry) {
                "Retrying operation in {0} seconds. Retry count: {1}." - $RetryIntervalInSeconds, $counter | Trace-Output
                Start-Sleep -Seconds $RetryIntervalInSeconds
            }
            else {
                throw $_
            }
        }
    }

    "StatusCode: {0} StatusDescription: {1}" -f $result.StatusCode, $result.StatusDescription | Trace-Output -Level:Verbose
    return $result
}
