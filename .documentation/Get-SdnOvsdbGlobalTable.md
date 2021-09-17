# Get-SdnOvsdbGlobalTable

## SYNOPSIS

## SYNTAX

### Default (Default)
```
Get-SdnOvsdbGlobalTable -ComputerName <String[]> [-Credential <PSCredential>] [<CommonParameters>]
```

### AsJob
```
Get-SdnOvsdbGlobalTable -ComputerName <String[]> [-Credential <PSCredential>] [-AsJob] [-PassThru]
 [-Timeout <Int32>] [<CommonParameters>]
```

## DESCRIPTION
{{ Fill in the Description }}

## EXAMPLES

### EXAMPLE 1
```
Get-SdnOvsdbGlobalTable -ComputerName 'Server01','Server02'
```

### EXAMPLE 2
```
Get-SdnOvsdbGlobalTable -ComputerName 'Server01','Server02' -Credential (Get-Credential)
```

### EXAMPLE 3
```
Get-SdnOvsdbGlobalTable -ComputerName 'Server01','Server02' -AsJob
```

### EXAMPLE 4
```
Get-SdnOvsdbGlobalTable -ComputerName 'Server01','Server02' -AsJob -PassThru
```

### EXAMPLE 5
```
Get-SdnOvsdbGlobalTable -ComputerName 'Server01','Server02' -AsJob -PassThru -Timeout 600
```

## PARAMETERS

### -ComputerName
Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
To specify the local computer, type the computer name, localhost, or a dot (.).
When the computer is in a different domain than the user, the fully qualified domain name is required

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
Specifies a user account that has permission to perform this action.
The default is the current user.

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: [System.Management.Automation.PSCredential]::Empty
Accept pipeline input: False
Accept wildcard characters: False
```

### -AsJob
Switch indicating to trigger a background job to perform the operation.

```yaml
Type: SwitchParameter
Parameter Sets: AsJob
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -PassThru
Switch indicating to wait for background job completes and display results to current session.

```yaml
Type: SwitchParameter
Parameter Sets: AsJob
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Timeout
Specify the timeout duration to wait before job is automatically terminated.
If omitted, defaults to 300 seconds.

```yaml
Type: Int32
Parameter Sets: AsJob
Aliases:

Required: False
Position: Named
Default value: 300
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
