# Test-SdnKIServiceFabricPartitionDatabaseSize

## SYNOPSIS
Validate the Service Fabric partition size for each of the services running on Network Controller.

## SYNTAX

```
Test-SdnKIServiceFabricPartitionDatabaseSize [[-NetworkController] <String[]>] [[-Credential] <PSCredential>]
 [<CommonParameters>]
```

## DESCRIPTION
{{ Fill in the Description }}

## EXAMPLES

### EXAMPLE 1
```
Test-SdnKIServiceFabricPartitionDatabaseSize
```

### EXAMPLE 2
```
Test-SdnKIServiceFabricPartitionDatabaseSize -NetworkController 'NC01','NC02'
```

### EXAMPLE 3
```
Test-SdnKIServiceFabricPartitionDatabaseSize -NetworkController 'NC01','NC02' -Credential (Get-Credential)
```

## PARAMETERS

### -NetworkController
Specifies the name or IP address of the network controller node on which this cmdlet operates.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: $Global:SdnDiagnostics.EnvironmentInfo.NC
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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
