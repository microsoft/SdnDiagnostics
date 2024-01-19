function Remove-SdnDiagnosticJob {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [System.String[]]$State = @("Completed","Failed"),

        [Parameter(Mandatory = $false)]
        [System.String]$Name
    )

    if (-NOT ([string]::IsNullOrEmpty($Name))) {
        $filteredJobs = Get-Job -Name $Name
    }
    else {
        $filteredJobs = Get-Job -Name "SdnDiag-*" | Where-Object {$_.State -iin $State}
    }

    if ($filteredJobs ) {
        $filteredJobs | Remove-Job -Force -ErrorAction SilentlyContinue
    }
}
