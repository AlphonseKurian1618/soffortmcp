targetScope = 'resourceGroup'

@description('Region of the existing development deployment.')
param location string = 'westus2'

@description('Azure/Entra object ID of the development operator importing APNs keys.')
param operatorObjectId string

@description('Optional operator IPv4 address for the one-time Key Vault import.')
param keyVaultOperatorIpAddress string = ''

@description('Existing AKS cluster name. This entrypoint never updates the cluster itself.')
param clusterName string = 'aks-soffortbackend-dev-wus2'

@description('Existing fixed outbound public IP resource name.')
param outboundPublicIpName string = 'pip-soffortbackend-dev-outbound-wus2'

@description('Existing ACR login server used by the application Helm release.')
param acrLoginServer string

@description('ACME email already used by the platform kustomization.')
param certificateEmail string

param entraIssuer string
param entraJwksUrl string
param entraTenantId string
param entraApiAudience string
param entraVscodeClientId string
param entraIosClientId string
param apnsKeyId string
param apnsPrivateKeySecretVersion string

@description('Git branch reconciled by the development-only bootstrap. Keep main outside review deployments.')
param gitBranch string = 'main'

var commonTags = {
  application: 'soffortbackend'
  environment: 'development'
  costCenter: 'soffort'
  budget: 'under-200-usd'
}

// Keep this bootstrap separate from main.bicep. Azure may preflight an unchanged
// AKS PUT when main is redeployed; this file safely creates only Phase 2 data
// services while the existing cluster remains completely untouched.
resource cluster 'Microsoft.ContainerService/managedClusters@2025-05-01' existing = {
  name: clusterName
}

resource outboundPublicIp 'Microsoft.Network/publicIPAddresses@2025-05-01' existing = {
  name: outboundPublicIpName
}

resource applicationIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: 'id-soffortbackend-app-dev'
  location: location
  tags: union(commonTags, {
    purpose: 'aks-cosmos-keyvault-workload-identity'
  })
}

resource applicationFederation 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2024-11-30' = {
  parent: applicationIdentity
  name: 'soffortbackend-service-account'
  properties: {
    issuer: cluster.properties.oidcIssuerProfile.issuerURL
    subject: 'system:serviceaccount:soffortbackend:soffortbackend'
    audiences: [
      'api://AzureADTokenExchange'
    ]
  }
}

resource approvalCosmos 'Microsoft.DocumentDB/databaseAccounts@2025-04-15' = {
  name: toLower('cosmos-soffort-dev-${uniqueString(subscription().id)}')
  location: location
  tags: commonTags
  kind: 'GlobalDocumentDB'
  properties: {
    databaseAccountOfferType: 'Standard'
    publicNetworkAccess: 'Enabled'
    disableLocalAuth: true
    disableKeyBasedMetadataWriteAccess: true
    minimalTlsVersion: 'Tls12'
    enableAutomaticFailover: false
    enableMultipleWriteLocations: false
    locations: [
      {
        locationName: location
        failoverPriority: 0
        isZoneRedundant: false
      }
    ]
    capabilities: [
      {
        name: 'EnableServerless'
      }
    ]
    consistencyPolicy: {
      defaultConsistencyLevel: 'Session'
    }
    networkAclBypass: 'None'
    networkAclBypassResourceIds: []
    ipRules: [
      {
        ipAddressOrRange: outboundPublicIp.properties.ipAddress
      }
    ]
    backupPolicy: {
      type: 'Periodic'
      periodicModeProperties: {
        backupIntervalInMinutes: 240
        backupRetentionIntervalInHours: 8
        backupStorageRedundancy: 'Local'
      }
    }
  }
}

resource approvalDatabase 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases@2025-04-15' = {
  parent: approvalCosmos
  name: 'soffortbackend'
  properties: {
    resource: {
      id: 'soffortbackend'
    }
  }
}

resource approvalContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2025-04-15' = {
  parent: approvalDatabase
  name: 'approval'
  properties: {
    resource: {
      id: 'approval'
      defaultTtl: -1
      partitionKey: {
        paths: [
          '/partition_key'
        ]
        kind: 'Hash'
        version: 2
      }
      indexingPolicy: {
        automatic: true
        indexingMode: 'consistent'
        includedPaths: [
          {
            path: '/*'
          }
        ]
        excludedPaths: [
          {
            path: '/"apns_token"/?'
          }
          {
            path: '/"public_jwk"/*'
          }
          {
            path: '/"display_name"/?'
          }
          {
            path: '/"display_name_snapshot"/?'
          }
          {
            path: '/"compact_jwe"/?'
          }
        ]
      }
    }
  }
}

resource cosmosDataContributor 'Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments@2025-04-15' = {
  parent: approvalCosmos
  name: guid(approvalCosmos.id, applicationIdentity.id, 'data-contributor')
  properties: {
    principalId: applicationIdentity.properties.principalId
    roleDefinitionId: '${approvalCosmos.id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002'
    scope: approvalCosmos.id
  }
}

resource approvalVault 'Microsoft.KeyVault/vaults@2024-11-01' = {
  // Keep this deterministic global name below Key Vault's 24-character cap.
  name: toLower('kv-sf-${uniqueString(subscription().id)}')
  location: location
  tags: commonTags
  properties: {
    tenantId: tenant().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Deny'
      ipRules: concat(
        [
          {
            value: outboundPublicIp.properties.ipAddress
          }
        ],
        empty(keyVaultOperatorIpAddress) ? [] : [
          {
            value: keyVaultOperatorIpAddress
          }
        ]
      )
      virtualNetworkRules: []
    }
  }
}

resource disclosureKey 'Microsoft.KeyVault/vaults/keys@2024-11-01' = {
  parent: approvalVault
  name: 'permi-disclosure'
  properties: {
    kty: 'RSA'
    keySize: 2048
    keyOps: [
      'encrypt'
      'decrypt'
    ]
    attributes: {
      enabled: true
    }
  }
}

var keyVaultSecretsUserRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '4633458b-17de-408a-b874-0445c86b69e6'
)
resource applicationVaultSecretsUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(approvalVault.id, applicationIdentity.id, keyVaultSecretsUserRoleId)
  scope: approvalVault
  properties: {
    principalId: applicationIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: keyVaultSecretsUserRoleId
  }
}

var keyVaultCryptoUserRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '12338af0-0e69-4776-bea7-57ae8d297424'
)
resource applicationVaultCryptoUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(approvalVault.id, applicationIdentity.id, keyVaultCryptoUserRoleId)
  scope: approvalVault
  properties: {
    principalId: applicationIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: keyVaultCryptoUserRoleId
  }
}

var keyVaultSecretsOfficerRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'
)
resource operatorVaultSecretsOfficer 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(approvalVault.id, operatorObjectId, keyVaultSecretsOfficerRoleId)
  scope: approvalVault
  properties: {
    principalId: operatorObjectId
    principalType: 'User'
    roleDefinitionId: keyVaultSecretsOfficerRoleId
  }
}

resource fluxExtension 'Microsoft.KubernetesConfiguration/extensions@2024-11-01' existing = {
  name: 'flux'
  scope: cluster
}

// Updating this child resource changes Flux substitutions only. The existing
// managed cluster remains an `existing` reference and receives no AKS PUT.
resource fluxConfiguration 'Microsoft.KubernetesConfiguration/fluxConfigurations@2025-04-01' = {
  name: 'soffortbackend-dev'
  scope: cluster
  properties: {
    scope: 'cluster'
    namespace: 'flux-system'
    sourceKind: 'GitRepository'
    suspend: false
    waitForReconciliation: false
    gitRepository: {
      url: 'https://github.com/AlphonseKurian1618/soffortmcp.git'
      provider: 'Generic'
      repositoryRef: {
        branch: gitBranch
      }
      syncIntervalInSeconds: 60
      timeoutInSeconds: 60
    }
    kustomizations: {
      'gateway-api': {
        path: './deploy/flux/dev/gateway-api'
        prune: true
        force: false
        wait: true
        syncIntervalInSeconds: 300
        retryIntervalInSeconds: 60
        timeoutInSeconds: 600
      }
      controllers: {
        path: './deploy/flux/dev/controllers'
        dependsOn: [
          'gateway-api'
        ]
        prune: true
        force: false
        wait: true
        syncIntervalInSeconds: 300
        retryIntervalInSeconds: 60
        timeoutInSeconds: 900
        postBuild: {
          substitute: {
            INGRESS_PUBLIC_IP_NAME: 'pip-soffortbackend-dev-ingress-wus2'
            INGRESS_PUBLIC_IP_RESOURCE_GROUP: resourceGroup().name
          }
        }
      }
      platform: {
        path: './deploy/flux/dev/platform'
        dependsOn: [
          'controllers'
        ]
        prune: true
        force: false
        wait: true
        syncIntervalInSeconds: 300
        retryIntervalInSeconds: 60
        timeoutInSeconds: 600
        postBuild: {
          substitute: {
            CERTIFICATE_EMAIL: certificateEmail
          }
        }
      }
      application: {
        path: './deploy/flux/dev/application'
        dependsOn: [
          'platform'
        ]
        prune: true
        force: false
        wait: false
        syncIntervalInSeconds: 60
        retryIntervalInSeconds: 60
        timeoutInSeconds: 600
        postBuild: {
          substitute: {
            ACR_LOGIN_SERVER: acrLoginServer
            ENTRA_ISSUER: entraIssuer
            ENTRA_JWKS_URL: entraJwksUrl
            ENTRA_TENANT_ID: entraTenantId
            ENTRA_API_AUDIENCE: entraApiAudience
            ENTRA_VSCODE_CLIENT_ID: entraVscodeClientId
            ENTRA_IOS_CLIENT_ID: entraIosClientId
            COSMOS_ENDPOINT: approvalCosmos.properties.documentEndpoint
            AZURE_WORKLOAD_CLIENT_ID: applicationIdentity.properties.clientId
            KEY_VAULT_URL: approvalVault.properties.vaultUri
            APNS_KEY_ID: apnsKeyId
            APNS_PRIVATE_KEY_SECRET_VERSION: apnsPrivateKeySecretVersion
          }
        }
      }
    }
  }
  dependsOn: [
    fluxExtension
  ]
}

output applicationClientId string = applicationIdentity.properties.clientId
output cosmosEndpoint string = approvalCosmos.properties.documentEndpoint
output keyVaultName string = approvalVault.name
output keyVaultUrl string = approvalVault.properties.vaultUri
output fluxConfigurationName string = fluxConfiguration.name
