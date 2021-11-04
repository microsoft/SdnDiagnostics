# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

class Issue {
    [boolean]$Detected;
    [System.String]$Recommendation;
    [System.String[]]$Reference
    [System.Object]$Property;
}
