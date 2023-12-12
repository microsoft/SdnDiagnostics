function Write-SdnDiagEvent {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [string]$Function,

        [Parameter(Mandatory=$false)]
        [TraceLevel]$Level = "Information",

        [Parameter(Mandatory=$false)]
        [string]$StackTrace
    )

    # Create a new event
    $diagEvent = [SdnDiagEvent]::new()
    $diagEvent.Message = $Message
    $diagEvent.Function = (Get-PSCallStack)[1].Command
    $diagEvent.Level = $Level

    # Log the event
    [SdnDiagEventChannel]::Log.LogEvent($diagEvent.ToString())
}
