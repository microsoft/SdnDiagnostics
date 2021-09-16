# Get-SdnDiagnosticLog

## SYNOPSIS
Collect the default enabled logs from SdnDiagnostics folder.

## SYNTAX

```
Get-SdnDiagnosticLog [-OutputDirectory] <FileInfo> [[-FromDate] <DateTime>] [<CommonParameters>]
```

## DESCRIPTION
{{ Fill in the Description }}

## EXAMPLES

### Example 1
```powershell
PS C:\> {{ Add example code here }}
```

{{ Add example description here }}

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

### -FromDate
Optional parameter that allows you to control how many hours worth of logs to retrieve from the system for the roles identified.
Default is 4 hours.
(Get-Date).AddHours(-4)

```yaml
Type: DateTime
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: (Get-Date).AddHours(-4)
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
