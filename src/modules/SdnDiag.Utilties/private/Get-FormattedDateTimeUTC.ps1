# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-FormattedDateTimeUTC {
    return ([DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))
}