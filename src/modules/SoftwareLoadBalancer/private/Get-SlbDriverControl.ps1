function Get-SlbDriverControl {
    if (-NOT (Get-Module -Name 'Microsoft.Cloudnet.Slb.Mux.MuxDriverControl')) {
        Import-Module 'C:\windows\System32\Microsoft.Cloudnet.Slb.Mux.MuxDriverControl.dll' -Force
    }

    return ([Microsoft.Cloudnet.Slb.Mux.Driver.SlbDriverControl]::new())
}
