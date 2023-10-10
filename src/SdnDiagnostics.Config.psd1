# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

@{
    # this enables an override of the default file type that is used when exporting objects to a file
    # when this is set to 'Custom', the default file type will be whatever is passed in the command
    # when this is set to anything else, the default file type will be whatever is set here
    # supported values are 'json', 'csv', 'txt', 'Custom'
    DefaultFileType = 'Custom'

    # this defines where the module will be installed
    # if this is not set, the default location will be C:\Program Files\WindowsPowerShell\Modules\SdnDiagnostics
    ModuleRootDir = 'C:\Program Files\WindowsPowerShell\Modules\SdnDiagnostics'
}
