# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

enum Status {
    Failure
    Success
}

class Health {
    [Status]$Status;
    [System.String]$Recommendation;
    [System.String[]]$Reference
    [System.Object]$Property;
}

