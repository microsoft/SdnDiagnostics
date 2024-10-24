$major = [int]4 # Major version number
$minor = [DateTime]::UtcNow.Year.ToString().Substring(2,2) + [DateTime]::UtcNow.Month.ToString().PadLeft(2,"0") # 2002, 2104, etc for current month
$patch = [DateTime]::UtcNow.Day.ToString().PadLeft(2, "0")

$hour = [DateTime]::UtcNow.Hour.ToString().TrimStart('0')
$minute = [DateTime]::UtcNow.Minute.ToString().TrimStart('0')
if ([string]::IsNullOrEmpty($minute)) { $minute = "1" }

$revision = "{0}{1}" -f $hour, $minute # creates a 4 digit number from the current hour and minute
$buildNumber = "{0}.{1}.{2}.{3}" -f $major, $minor, $patch, $revision.Trim()

[Environment]::SetEnvironmentVariable("CUSTOM_VERSION", $buildNumber, "User")
Write-Host "##vso[task.setvariable variable=CUSTOM_VERSION;]${buildNumber}"

return $buildNumber
