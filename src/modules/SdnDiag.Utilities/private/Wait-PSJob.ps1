function Wait-PSJob {
    <#
    .SYNOPSIS
        Monitors jobs to ensure they complete or terminate if any particular job is taking too long
    .PARAMETER Name
        The job name to monitor
    .PARAMETER Activity
        Description of the job that is being performed
    .PARAMETER ExecutionTimeOut
        Total period to wait for jobs to complete before stopping jobs and progressing forward in scripts. If omitted, defaults to 600 seconds
    .PARAMETER PollingInterval
        How often you want to query job status. If omitted, defaults to 1 seconds
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.String]$Name,

        [Parameter(Mandatory = $false)]
        [System.String]$Activity = (Get-PSCallStack)[1].Command,

        [Parameter(Mandatory = $false)]
        [int]$ExecutionTimeOut = 600,

        [Parameter(Mandatory = $false)]
        [int]$PollingInterval = 1
    )

    try {
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        "JobName: {0} PollingInterval: {1} seconds ExecutionTimeout: {2} seconds" -f $Name, $PollingInterval, $ExecutionTimeOut | Trace-Output -Level:Verbose

        # Loop while there are running jobs
        while ((Get-Job -Name $Name).State -ieq 'Running') {

            # get the job details and write progress
            $job = Get-Job -Name $Name
            $runningChildJobs = $job.ChildJobs | Where-Object { $_.State -ieq 'Running' }
            $jobCount = $job.ChildJobs.Count
            $runningJobCount = $runningChildJobs.Count
            $percent = [math]::Round((($jobcount - $runningJobCount) / $jobCount * 100), 2)

            $status = "Progress: {0}%. Waiting for {1}" -f $percent, ($runningChildJobs.Location -join ', ')
            Write-Progress -Activity $Activity -Status $status -PercentComplete $percent -Id $job.Id

            # check the stopwatch and break out of loop if we hit execution timeout limit
            if ($stopWatch.Elapsed.TotalSeconds -ge $ExecutionTimeOut) {
                Get-Job -Name $Name | Stop-Job -Confirm:$false
                throw New-Object System.TimeoutException("Unable to complete operation within the specified timeout period")
            }

            # pause the loop per polling interval value
            Start-Sleep -Seconds $PollingInterval
        }

        $stopWatch.Stop()
        $job = Get-Job -Name $Name

        # Ensure that we complete all jobs for write-progress to clear the progress bars
        Write-Progress -Activity $Activity -Id $job.Id -Completed

        # Output results of the job status to the operator
        if ($job.State -ne "Completed") {
            [System.String]$outputFolder = "{0}\PSRemoteJob_Failures\{1}" -f (Get-WorkingDirectory), $Name

            "[{0}] Operation {1}. Total Elapsed Time: {2}" -f $Name, $job.State, $stopwatch.Elapsed.TotalSeconds | Trace-Output -Level:Warning

            # Identify all failed child jobs and present to the operator
            $failedChildJobs = $job.ChildJobs | Where-Object { $_.State -ine 'Completed' }
            foreach ($failedChildJob in $failedChildJobs) {
                "[{0}] {1} for {2} is reporting state: {3}." -f $Name, $failedChildJob.Name, $failedChildJob.Location, $failedChildJob.State | Trace-Output -Level:Warning

                # do our best to capture the failing exception that was returned from the remote job invocation
                # due to ps remoting bug as outlined in https://github.com/PowerShell/PowerShell/issues/9585 we may not capture everything and may add additional details to screen
                $failedChildJob | Receive-Job -Keep -ErrorAction Continue *>&1 | Export-ObjectToFile -FilePath $outputFolder -Name $failedChildJob.Name -FileType 'txt'
            }
        }
        else {
            "[{0}] Operation {1}. Total Elapsed Time: {2}" -f $Name, $job.State, $stopwatch.Elapsed.TotalSeconds | Trace-Output -Level:Verbose
        }

        return (Get-Job -Name $Name | Receive-Job)
    }
    catch {
       $_ | Trace-Output -Level:Error
    }
}
