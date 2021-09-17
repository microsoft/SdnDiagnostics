# Test-SdnProviderNetwork

## SYNOPSIS
Performs ICMP tests across the computers defined to confirm that jumbo packets are able to successfully traverse between the provider addresses on each host

## SYNTAX

```
Test-SdnProviderNetwork [[-ComputerName] <String[]>] [[-Credential] <PSCredential>] [<CommonParameters>]
```

## DESCRIPTION
{{ Fill in the Description }}

## EXAMPLES

### EXAMPLE 1
```
Test-SdnProviderNetwork
```

### EXAMPLE 2
```
Test-SdnPRoviderNetwork -ComputerName 'Server01','Server02' -Credential (Get-Credential)
```

## PARAMETERS

### -ComputerName
Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: $global:SdnDiagnostics.EnvironmentInfo.Host
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
