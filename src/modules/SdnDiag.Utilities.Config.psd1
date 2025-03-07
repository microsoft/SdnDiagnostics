# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

@{
    FolderPathsAllowedForCleanup = @(
        "C:\Windows\Tracing\SdnDiag"
        "C:\Windows\Tracing\SdnDiag\*"
    )
    DefaultModuleDirectory = "C:\Program Files\WindowsPowerShell\Modules\SdnDiagnostics"
    WorkingDirectory = "C:\Windows\Tracing\SdnDiag"
    HashKeys = @{
        PSCommonParams = @(
            'Verbose',
            'Debug',
            'ErrorAction',
            'WarningAction',
            'InformationAction',
            'ErrorVariable',
            'WarningVariable',
            'InformationVariable',
            'OutVariable',
            'OutBuffer'
        ),
        SdnResourceParams = @(
            'ApiVersion',
            'InstanceId',
            'NcUri',
            'NcRestCertificate',
            'NcRestCredential',
            'Resource',
            'ResourceId',
            'ResourceRef',
            'ResourceType'
        ),
        RemoteComputerParams = @(
            'ComputerName',
            'Credential'
        )
    }
}
