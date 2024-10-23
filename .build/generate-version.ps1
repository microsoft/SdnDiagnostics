$major = [int]4 # Major version number
$minor = [DateTime]::UtcNow.Year.ToString().Substring(2,2) + [DateTime]::UtcNow.Month.ToString().PadLeft(2,"0") # 2002, 2104, etc for current month
$patch = [DateTime]::UtcNow.Day.ToString().PadLeft(2, "0")
$revision = "{0:d2}{1:d2}" -f ([DateTime]::UtcNow.Hour),([DateTime]::UtcNow.Minute) # creates revision based on hour, minute and second
$buildNumber = "{0}.{1}.{2}.{3}" -f $major, $minor, $patch, $revision

[Environment]::SetEnvironmentVariable("CUSTOM_VERSION", $buildNumber, "User")
Write-Host "##vso[task.setvariable variable=CUSTOM_VERSION;]${buildNumber}"

return $buildNumber
