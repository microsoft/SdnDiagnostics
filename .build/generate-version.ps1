$major = [int]4 # Major version number
$minor = [DateTime]::UtcNow.Year.ToString().Substring(2,2) + [DateTime]::UtcNow.Month.ToString().PadLeft(2,"0") # 2002, 2104, etc for current month

# we want to generate the patch number based on the current day
# this will return int32 value so should be between 1 and 31
$patch = [DateTime]::UtcNow.Day

# we want to generate the revision number based on the current hour and minute
# this can be between 2-4 digit number depending on the hour and minute
# we want to make sure that the hour is not 0 and does not have a leading zero
[int]$hour = [DateTime]::UtcNow.Hour
if ($hour -ieq 0) {$hour++}
[int]$minute = [DateTime]::UtcNow.Minute.ToString().PadLeft(2,"0")
if ($minute -ieq 0) {$minute++}
$revision = "{0}{1}" -f $hour.ToString().Trim(), $minute.ToString().Trim()

# we now have our build number
# we want to format as #.YYMM.DD.HHMM : 8.2104.12.1120
$buildNumber = "{0}.{1}.{2}.{3}" -f $major, $minor, $patch.ToString().Trim(), $revision.Trim()

[Environment]::SetEnvironmentVariable("CUSTOM_VERSION", $buildNumber, "Process")
Write-Host "##vso[task.setvariable variable=CUSTOM_VERSION]${buildNumber}"
Write-Host "##vso[task.setvariable variable=CUSTOM_VERSION;isOutput=true]${buildNumber}"

return $buildNumber
