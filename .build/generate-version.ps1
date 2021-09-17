$referenceDate = ([datetime]"2021-07-15 00:00:00Z").ToUniversalTime()

$major = [int]((([DateTime]::UtcNow - $referenceDate).Days / 365) +1) # years since reference date
$minor = [DateTime]::UtcNow.Year.ToString().Substring(2,2) + [DateTime]::UtcNow.Month.ToString().PadLeft(2,"0") # 2002, 2104, etc for current month
$patch = ([DateTime]::UtcNow - $referenceDate).Days # days since reference date
$revision = "{0:d2}{1:d2}{2:d2}" -f ([DateTime]::UtcNow.Hour),([DateTime]::UtcNow.Minute),([DateTime]::UtcNow.Second) # creates revision based on hour, minute and second
$buildNumber = "{0}.{1}.{2}.{3}" -f $major, $minor, $patch, $revision

[Environment]::SetEnvironmentVariable("SdnDiagCustomBuildNumber", $buildNumber)  # This will allow you to use it from env var in later steps of the same phase
Write-Host "Generating build version: $($buildNumber)"  # This will update build number on your build