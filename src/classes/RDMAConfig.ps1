class RDMAConfig {
    [System.String]$Name;
    [System.String]$InterfaceDescription;
    [System.String]$AdapterType;
    [System.Boolean]$MaxQueueConfigIsValid;
    [System.Boolean]$QoSEnabled;
    [System.Boolean]$QoSOperationalFlowControlEnabled;
    [System.Boolean]$RdmaConfigurationIsValid;
    [System.Boolean]$RdmaEnabled;
    [System.Boolean]$SMBInterfacesDetected;

    isValid() {
        if ($this.QoSEnabled -and $this.RdmaEnabled -and $this.MaxQueueConfigIsValid -and $this.QoSOperationalFlowControlEnabled -and $this.SMBInterfacesDetected) {
            $this.RdmaConfigurationIsValid = $true
        }
    }
}
