# Get-SdnServiceFabricService

## SYNOPSIS
Gets a list of Service Fabric services from Network Controller.

## SYNTAX

### NamedService (Default)
```
Get-SdnServiceFabricService [-ApplicationName <String>] [-ServiceName <String>] [-NetworkController <String[]>]
 [-Credential <PSCredential>] [<CommonParameters>]
```

### NamedServiceTypeName
```
Get-SdnServiceFabricService [-ApplicationName <String>] [-ServiceTypeName <String>]
 [-NetworkController <String[]>] [-Credential <PSCredential>] [<CommonParameters>]
```

## DESCRIPTION
{{ Fill in the Description }}

## EXAMPLES

### EXAMPLE 1
```
Get-SdnServiceFabricService -NetworkController 'Prefix-NC01' -Credential (Get-Credential)
```

### EXAMPLE 2
```
Get-SdnServiceFabricService -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -ServiceTypeName 'ApiService'
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

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ServiceTypeName
A service fabric service TypeName, such as VSwitchService

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
