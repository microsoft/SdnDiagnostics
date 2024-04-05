function Confirm-IsAdmin {
    if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw New-Object System.UnauthorizedAccessException("You must be an administrator to perform this operation. Run PowerShell as an Administrator and import the module again.")
    }
}
