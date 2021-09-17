# Convert-EtwTraceToTxt

## SYNOPSIS
Used to convert existing etw (.etl) provider traces into text readable format

## SYNTAX

```
Convert-EtwTraceToTxt [-FileName] <FileInfo> [[-Destination] <FileInfo>] [[-Overwrite] <String>]
 [[-Report] <String>] [<CommonParameters>]
```

## DESCRIPTION
{{ Fill in the Description }}

## EXAMPLES

### EXAMPLE 1
```
Convert-EtwTraceToTxt -FileName "C:\Temp\CSS_SDN\Trace.etl"
```

### EXAMPLE 2
```
Convert-EtwTraceToTxt -FileName "C:\Temp\CSS_SDN\Trace.etl" -Destination "C:\Temp\CSS_SDN_NEW\trace.txt"
```

### EXAMPLE 3
```
Convert-EtwTraceToTxt -FileName "C:\Temp\CSS_SDN\Trace.etl" -Overwrite Yes
```

### EXAMPLE 4
```
Convert-EtwTraceToTxt -FileName "C:\Temp\CSS_SDN\Trace.etl" -Report Yes
```

## PARAMETERS

### -FileName
ETL trace file path and name to convert

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

### -Destination
Output file name and directory.
If omitted, will use the FileName path and base name.

```yaml
Type: FileInfo
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Overwrite
Overwrites existing files.
If omitted, defaults to no.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: No
Accept pipeline input: False
Accept wildcard characters: False
```

### -Report
Generates an HTML report.
If omitted, defaults to no.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: No
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
