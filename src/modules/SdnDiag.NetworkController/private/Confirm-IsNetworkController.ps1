function Confirm-IsNetworkController {
    $config = Get-SdnModuleConfiguration -Role 'NetworkController'
    $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
    if (-NOT ($confirmFeatures)) {
        throw "The current machine is not a NetworkController, run this on NetworkController"
    }
}

