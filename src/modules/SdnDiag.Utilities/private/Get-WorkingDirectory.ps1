function Get-WorkingDirectory {

    # check to see if the working directory has been configured into cache
    # otherwise set the cache based on what we have defined within our configuration file
    if ([String]::IsNullOrEmpty($Script:SdnDiagnostics_Utilities.Cache.WorkingDirectory)) {
        $Script:SdnDiagnostics_Utilities.Cache.WorkingDirectory = $Script:SdnDiagnostics_Utilities.Config.WorkingDirectory
    }

    return [System.String]$Script:SdnDiagnostics_Utilities.Cache.WorkingDirectory
}
