function Get-SlbClient {

    # as we are dependent on the assemblies contained on Network Controller
    # we need to ensure we are running on Network Controller
    $config = Get-SdnModuleConfiguration -Role 'NetworkController'
    $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
    if (-NOT ($confirmFeatures)) {
        throw New-Object System.NotSupportedException("The current machine is not a NetworkController, run this on NetworkController.")
    }

    $rootDir = "$env:SystemRoot\NetworkController"
    $null = [Reflection.Assembly]::LoadFrom("$rootDir\SharedAssemblies\Microsoft.CloudNet.Slb.Utilities.SlbClient.dll");
    $null = [Reflection.Assembly]::LoadFrom("$rootDir\Framework\Microsoft.NetworkController.Utilities.dll");
    $null = [Reflection.Assembly]::LoadFrom("$rootDir\Framework\Microsoft.NetworkController.ServiceModule.dll");

    [Microsoft.Cloudnet.Slb.Utilities.SlbClient.SlbManagerConnectionFactory]::SlbClientInitializeWithDefaultSettings();
    [Microsoft.Cloudnet.Slb.Utilities.SlbClient.SlbManagerConnectionFactory]::UseInteractiveLogon = $false
    [Microsoft.Cloudnet.Slb.Utilities.SlbClient.SlbManagerConnectionFactory]::EnableBlockingNotifications = $true;

    $slbClient = [Microsoft.Cloudnet.Slb.Utilities.SlbClient.SlbClient]::new()
    return $slbClient
}
