# Get-SdnSlbStateInformation

## SYNOPSIS
Generates an aggregated report of Virtual IPs (VIPs) in the environment and their current status as reported by the MUXes.

## SYNTAX

```
Get-SdnSlbStateInformation [-NcUri] <Uri> [[-Credential] <PSCredential>] [[-ExecutionTimeOut] <Int32>]
 [[-PollingInterval] <Int32>] [<CommonParameters>]
```

## DESCRIPTION
{{ Fill in the Description }}

## EXAMPLES

### EXAMPLE 1
```
Get-SdnSlbStateInformation
```

### EXAMPLE 2
```
Get-SdnSlbStateInformation -Credential (Get-Credential)
```

### EXAMPLE 3
```
Get-SdnSlbStateInformation -ExecutionTimeout 1200
```

## PARAMETERS

### -NcUri
{{ Fill NcUri Description }}

```yaml
Type: Uri
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
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
Position: 2
Default value: [System.Management.Automation.PSCredential]::Empty
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExecutionTimeOut
Specify the timeout duration to wait before automatically terminated.
If omitted, defaults to 600 seconds.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: 600
Accept pipeline input: False
Accept wildcard characters: False
```

### -PollingInterval
Interval in which to query the state of the request to determine completion.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: 5
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
