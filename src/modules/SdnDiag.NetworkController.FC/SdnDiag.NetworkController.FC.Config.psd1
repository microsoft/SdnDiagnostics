# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

@{
    Name = "NetworkControllerFC"
    WindowsFeature = @(
        "NetworkController"
    )
    RequiredModules = @(
        "NetworkController"
    )
    Properties = @{
        CommonPaths = @{}
        EventLogProviders = @()
        RegKeyPaths = @()
        Services = @{}
    }
}
