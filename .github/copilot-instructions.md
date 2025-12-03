# GitHub Copilot Instructions for SdnDiagnostics

## Project Overview
SdnDiagnostics is a PowerShell module for diagnosing and troubleshooting Software Defined Networking (SDN) infrastructure in Microsoft environments, including Azure Stack HCI and Windows Server deployments.

## Code Style and Conventions

### PowerShell Standards
- Follow PowerShell best practices and the [PowerShell Practice and Style Guide](https://poshcode.gitbook.io/powershell-practice-and-style)
- Use approved verbs for function names (Get-, Set-, New-, Remove-, etc.)
- Use PascalCase for function names and parameters
- Use camelCase for local variables
- Include comprehensive comment-based help for all exported functions

### Function Structure
- Always include `[CmdletBinding()]` attribute for advanced functions
- Use parameter sets when functions have mutually exclusive parameters
- Include proper parameter validation attributes (`Mandatory`, `ValidateSet`, `ValidateScript`, etc.)
- Use `ShouldProcess` pattern for functions that make changes (with `-Confirm` and `-WhatIf` support)
- Always include proper error handling with try/catch blocks

### Error Handling
- Use `Trace-Output` for logging instead of `Write-Host` or `Write-Verbose`
- Pipe exceptions to `Trace-Exception` in catch blocks
- Always include both `Trace-Exception` and `Write-Error` in catch blocks
- Return meaningful error messages to users

Example:
```powershell
try {
    # Function logic
}
catch {
    $_ | Trace-Exception
    $_ | Write-Error
}
```

# Logging and Tracing
- Use Trace-Output function for all logging with appropriate -Level parameter
  -Level:Verbose for detailed debug information
  -Level:Information for general information (default)
  -Level:Warning for warnings
  -Level:Error for errors
  -Level:Exception for exceptions (handled by Trace-Exception)
  -Level:Success for successful operations

# Module Organization
Place role-specific functions in appropriate module files:
- `SdnDiag.Common.psm1` - Functions common to all roles
- `SdnDiag.Gateway.psm1` - Gateway-specific functions
- `SdnDiag.LoadBalancerMux.psm1` - Load balancer MUX functions
- `SdnDiag.NetworkController.psm1` - Network Controller functions
- `SdnDiag.Server.psm1` - Server/host-specific functions
- `SdnDiag.Utilities.psm1` - Utility helper functions

# Remote Execution
- Use `New-PSRemotingSession` for creating remote sessions
- Use `Invoke-PSRemoteCommand` for executing commands remotely. This function should handle session management and error handling.
- Always pass `$Credential` parameter for remote operations

# REST API Interactions
- Use `Invoke-RestMethodWithRetry` or `Invoke-WebRequestWithRetry` for Network Controller REST API calls
- Support both certificate and credential-based authentication
- Always include parameter sets for `RestCertificate` and `RestCredential`
- Use `@ncRestParams` splatting pattern for REST parameters

# Data Collection
- Use `Initialize-DataCollection` to prepare output directories and validate disk space
- Use `Export-ObjectToFile` to save results with consistent formatting
- Support `-OutputDirectory` parameter for all data collection functions
- Include time range parameters (`-FromDate`, `-ToDate`) where applicable

# Credential Handling
- Use `[System.Management.Automation.PSCredential]` type
- Default to `[System.Management.Automation.PSCredential]::Empty`
- Include `[System.Management.Automation.Credential()]` attribute

Example:
```powershell
[Parameter(Mandatory = $false)]
[System.Management.Automation.PSCredential]
[System.Management.Automation.Credential()]
$Credential = [System.Management.Automation.PSCredential]::Empty
```

# Documentation
- Include synopsis, description, parameter descriptions, and examples
- Use proper markdown formatting in comment-based help
- Document any prerequisites or dependencies
- Include related links where applicable

Common Patterns
Network Controller REST Parameter Pattern
```powershell
$ncRestParams = @{
    NcUri = $NcUri
    ErrorAction = 'Stop'
}

switch ($PSCmdlet.ParameterSetName) {
    'RestCertificate' { $ncRestParams.Add('NcRestCertificate', $NcRestCertificate) }
    'RestCredential' { $ncRestParams.Add('NcRestCredential', $NcRestCredential) }
}

$result = Get-SdnResource @ncRestParams -ResourceRef $resourceRef
```

# Security Best Practices
- Never log credentials or secrets
- Use SecureString for password parameters
- Validate user input with appropriate attributes
- Check for admin privileges when required using `Confirm-IsAdmin`
