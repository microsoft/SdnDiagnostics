# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

@{
    Name = "NetworkController_SF"
    WindowsFeature = @(
        "NetworkController"
    )
    RequiredModules = @()
    Properties = @{
        CommonPaths = @{
            serviceFabricLogDirectory = @(
                "C:\ProgramData\Microsoft\Service Fabric\log\Traces"
                "C:\ProgramData\Microsoft\Service Fabric\log\OperationalTraces"
                "C:\ProgramData\Microsoft\Service Fabric\log\QueryTraces"
                "C:\ProgramData\Microsoft\Service Fabric\log\CrashDumps"
                "C:\ProgramData\Microsoft\Service Fabric\log\PerformanceCounters_WinFabPerfCtrFolder"
            )
        }
        EventLogProviders = @(
            "Microsoft-ServiceFabric*"
        )
        RegKeyPaths = @()
        Services = @{
            FabricHostSvc = @{
                Properties = @{
                    DisplayName = "Service Fabric Host Service"
                }
            }
        }
    }
}
