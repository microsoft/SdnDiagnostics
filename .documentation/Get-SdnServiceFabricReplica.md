# Get-SdnServiceFabricReplica

## SYNOPSIS
Gets Service Fabric replicas of a partition from Network Controller.

## SYNTAX

### NamedService (Default)
```
Get-SdnServiceFabricReplica [-ApplicationName <String>] -ServiceName <String> [-NetworkController <String[]>]
 [-Credential <PSCredential>] [-Primary] [<CommonParameters>]
```

### NamedServiceTypeName
```
Get-SdnServiceFabricReplica [-ApplicationName <String>] [-ServiceTypeName <String>]
 [-NetworkController <String[]>] [-Credential <PSCredential>] [-Primary] [<CommonParameters>]
```

## DESCRIPTION
{{ Fill in the Description }}

## EXAMPLES

### EXAMPLE 1
```
Get-SdnServiceFabricReplica -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -ServiceTypeName 'ApiService'
```

### EXAMPLE 2
```
Get-SdnServiceFabricReplica -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -ServiceName 'fabric:/NetworkController/ApiService'
```

## PARAMETERS

### -ApplicationName
A service fabric application name that exists on the provided ring, such as fabric:/NetworkController.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: Fabric:/NetworkController
Accept pipeline input: False
Accept wildcard characters: False
```

### -ServiceName
A service fabric service name that is under the provided ApplicationName on the provided ring, such as fabric:/NetworkController/ApiService.

```yaml
Type: String
Parameter Sets: NamedService
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ServiceTypeName
A service fabric service TypeName, such as VSwitchService.

```yaml
Type: String
Parameter Sets: NamedServiceTypeName
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -NetworkController
Specifies the name of the network controller node on which this cmdlet operates.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
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
Position: Named
Default value: [System.Management.Automation.PSCredential]::Empty
Accept pipeline input: False
Accept wildcard characters: False
```

### -Primary
{{ Fill Primary Description }}

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
