# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

enum Status {
    Failure
    Success
}

class Insight {
    [System.Guid]$Id;
    [System.String]$Description;
    [System.String]$Reference;
    [System.Object]$Property;
    hidden [System.Object]$Remediation
}

class IssueInsight : Insight {
    [boolean]$IssueFound = $false;

    [void] SetIssueFound(){
        $this.IssueFound = $true
    }
}

class HealthInsight : Insight {
    [Status]$Status = 'Success';

    [void] SetFailure(){
        $this.Status = 'Failure'
    }
}
