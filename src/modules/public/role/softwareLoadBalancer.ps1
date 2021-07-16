function Get-SdnSlbStateInformation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [int]$ExecutionTimeOut = 900,
    
        [Parameter(Mandatory = $false)]
        [int]$PollingInterval = 5
    )

    try {
        [System.String]$uri = "{0}/networking/v1/diagnostics/slbstate" -f $NcUri.AbsoluteUri
        "Gathering SLB state information from {0}" -f $uri | Trace-Output -Level:Verbose

        $stopWatch =  [system.diagnostics.stopwatch]::StartNew()

        if($Credential -ne [System.Management.Automation.PSCredential]::Empty){
            $putResult = Invoke-WebRequest -Headers @{"Accept"="application/json"} `
                -Content "application/json; charset=UTF-8" `
                -Uri $uri `
                -Body "{}" `
                -Method PUT `
                -UseBasicParsing `
                -Credential $Credential
        }
        else {
            $putResult = Invoke-WebRequest -Headers @{"Accept"="application/json"} `
                -Content "application/json; charset=UTF-8" `
                -Uri $uri `
                -Body "{}" `
                -Method PUT `
                -UseBasicParsing `
                -UseDefaultCredentials
        }

        $resultObject = ConvertFrom-Json $putResult.Content
        $operationId = $resultObject.properties.operationId
        [System.String]$operationURI = "{0}/{1}" -f $uri, $operationId

        while($true){
            if($stopWatch.Elapsed.TotalSeconds -gt $ExecutionTimeOut){
                $msg = "Unable to get results for OperationId: {0}. Operation timed out" -f $operationId
                throw New-Object System.TimeoutException($msg)
            }

            Start-Sleep -Seconds $PollingInterval

            if($Credential){
                $stateResult = Invoke-WebRequest -Uri $operationURI `
                -Method Get `
                -UseBasicParsing `
                -Credential $Credential
            }
            else {
                $stateResult = Invoke-WebRequest -Uri $operationURI `
                -Method Get `
                -UseBasicParsing `
                -UseDefaultCredentials
            }

            if(($stateResult | ConvertFrom-Json).properties.provisioningState -ine 'Updating'){
                break
            }
        }

        $stopWatch.Stop()
        
        if($stateResult.properties.provisioningState -ine 'Succeeded'){
            $msg = "Unable to get results for OperationId: {0}. {1}" -f $operationId, $stateResult.properties
            throw New-Object System.Exception($msg)
        }
        else {
            return $stateResult.Content
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}