function Invoke-SdnRemediationAction {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.IO.FileInfo]$Path = "$PSScriptRoot\remediations",

        [Parameter(Mandatory = $true)]
        [System.String]$Action,

        [Parameter(Mandatory = $false)]
        [System.Collections.Hashtable]$RuntimeParameters
    )

    try {
        $actionPlanPath = "$(Join-Path -Path $Path.FullName -ChildPath $Action).ps1"
        if (Test-Path -Path $actionPlanPath) {
            "Executing remediation action {0} with runtime parameters: {1}" -f $Action, ($RuntimeParameters | Out-String) | Trace-Output
            $result = & $actionPlanPath @RuntimeParameters
        }

        if($result) {
            "Remediation action {0} returned status of {1}" -f $Action, $result | Trace-Output
        }
        else {
            "Remediation action {0} returned status of {1}" -f $Action, $result | Trace-Output -Level:Error
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
