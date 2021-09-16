# Invoke-SdnGetNetView

## SYNOPSIS
Invokes Get-Netview function on the specified ComputerNames.

## SYNTAX

```
Invoke-SdnGetNetView [-OutputDirectory] <FileInfo> [[-BackgroundThreads] <Int32>] [-SkipAdminCheck] [-SkipLogs]
 [-SkipNetshTrace] [-SkipCounters] [-SkipVm] [<CommonParameters>]
```

## DESCRIPTION
{{ Fill in the Description }}

## EXAMPLES

### EXAMPLE 1
```
Invoke-SdnGetNetView -ComputerName (Get-SdnServer -NcUri $uri -ManagementAddressOnly)
```

## PARAMETERS

### -OutputDirectory
Specifies a specific path and folder in which to save the files.

```yaml
Type: FileInfo
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -BackgroundThreads
Maximum number of background tasks, from 0 - 16.
Defaults to 5.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: 5
Accept pipeline input: False
Accept wildcard characters: False
```

### -SkipAdminCheck
If present, skip the check for admin privileges before execution.
Note that without admin privileges, the scope and
usefulness of the collected data is limited.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -SkipLogs
If present, skip the EVT and WER logs gather phases.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -SkipNetshTrace
If present, skip the Netsh Trace data gather phases.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -SkipCounters
If present, skip the Windows Performance Counters (WPM) data gather phases.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -SkipVm
{{ Fill SkipVm Description }}

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
