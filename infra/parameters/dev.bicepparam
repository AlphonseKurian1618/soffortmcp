using '../main.bicep'

// Values tied to the owner or External ID tenant are supplied by the protected
// GitHub environment or deploy-infra.sh, never committed to this file.
param location = 'westus2'
param nodeVmSize = 'Standard_D4pls_v6'

