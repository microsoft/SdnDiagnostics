# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Add-Type -TypeDefinition @"
    using System;
    using System.Diagnostics.Tracing;

    [EventSource(Name = "SdnDiagnostics")]
    public class SdnDiagEventChannel : EventSource {
        public static SdnDiagEventChannel Log = new SdnDiagEventChannel();

        [Event(1, Level = EventLevel.Informational)]
        public void LogEvent(string message) {
            if (IsEnabled()) WriteEvent(1, message);
        }
    }
"@

# base class for events. All events should have the properties defined in this class
class SdnDiagEvent {
    [guid]$ActivityId # used to correlate events
    [DateTime]$OccurrenceTime = [System.DateTime]::UtcNow
    [TraceLevel]$Level = "Information"
    [string]$Message
    [string]$Function
    [string]$TruncatedStackTrace
}

enum TraceLevel {
    Error
    Exception
    Information
    Success
    Verbose
    Warning
}

enum SdnModules {
    Common
    Gateway
    NetworkController
    Server
    LoadBalancerMux
    Utilities
}
