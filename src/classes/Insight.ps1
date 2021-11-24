# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

class Insight {
    [System.Guid]$Id;
    [boolean]$Detected;
    [System.String]$Action;
    hidden [System.String]$Description;
    [System.String]$Documentation;
    [System.Object]$Property;
}
