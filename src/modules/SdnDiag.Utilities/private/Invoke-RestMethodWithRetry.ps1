function Invoke-RestMethodWithRetry {

    [CmdletBinding(DefaultParameterSetName = 'Credential')]
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
        [System.Object]$Body,

        [Parameter(Mandatory = $false)]
        [Switch] $DisableKeepAlive,

        [Parameter(Mandatory = $false)]
        [Switch] $UseBasicParsing,

        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [X509Certificate]$Certificate,

        [Parameter(Mandatory = $false, ParameterSetName = 'Credential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutInSec = 600,

        [Parameter(Mandatory = $false)]
        [Switch]$Retry,

        [Parameter(Mandatory = $false)]
        [Int]$MaxRetry = 3,

        [Parameter(Mandatory = $false)]
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

    if ($DisableKeepAlive) {
        $params.Add('DisableKeepAlive', $true)
    }

    if ($UseBasicParsing) {
        $params.Add('UseBasicParsing', $true)
    }

    switch ($PSCmdlet.ParameterSetName) {
        'Certificate' {
            $params.Add('Certificate', $Certificate)
        }
        'Credential' {
            if ($Credential -ne [System.Management.Automation.PSCredential]::Empty -and $null -ne $Credential) {
                $params.Add('Credential', $Credential)
            }
            else {
                $params.Add('UseDefaultCredentials', $true)
            }
        }
    }

    $counter = 0
    while ($true) {
        $counter++

        try {
            "Performing {0} request to uri {1}" -f $Method, $Uri | Trace-Output -Level:Verbose
            if ($Body) {
                if ($Body -is [Hashtable]) {
                    "Body:`n`t{0}" -f ($Body | ConvertTo-Json -Depth 10) | Trace-Output -Level:Verbose
                }
                else {
                    "Body:`n`t{0}" -f ($Body) | Trace-Output -Level:Verbose
                }
            }

            $result = Invoke-RestMethod @params

            break
        }
        catch {
            if (($counter -le $MaxRetry) -and $Retry) {
                "Retrying operation in {0} seconds. Retry count: {1}." - $RetryIntervalInSeconds, $counter | Trace-Output
                Start-Sleep -Seconds $RetryIntervalInSeconds
            }
            else {
                $_ | Trace-Exception
                throw $_
            }
        }
    }

    return $result
}
