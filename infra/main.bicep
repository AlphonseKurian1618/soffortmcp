targetScope = 'resourceGroup'

@description('All workload resources are kept in West US 2 for the selected budget model.')
param location string = 'westus2'

@description('Pinned AKS Kubernetes patch selected by scripts/preflight.sh.')
param kubernetesVersion string

@allowed([
  'Standard_D4pls_v6'
  'Standard_D4pls_v5'
])
@description('ARM64 system-node SKU. No other size is permitted in development.')
param nodeVmSize string = 'Standard_D4pls_v6'

@description('Azure/Entra object ID of the human development operator.')
param operatorObjectId string

@description('Email used by the public Let\'s Encrypt ACME account.')
param certificateEmail string

@description('Exact Entra External ID v2 issuer URL.')
param entraIssuer string

@description('Exact Entra External ID JWKS URL.')
param entraJwksUrl string

@description('External ID tenant GUID expected in the tid claim.')
param entraTenantId string

@description('API application client ID expected in the aud claim.')
param entraApiAudience string

@description('VS Code public-client ID expected in azp/appid.')
param entraVscodeClientId string

var application = 'soffortbackend'
var environment = 'development'
var clusterName = 'aks-soffortbackend-dev-wus2'
var nodeResourceGroupName = 'rg-soffortbackend-dev-wus2-nodes'
var ingressPublicIpName = 'pip-soffortbackend-dev-ingress-wus2'
var outboundPublicIpName = 'pip-soffortbackend-dev-outbound-wus2'
var repository = 'AlphonseKurian1618/soffortmcp'
var commonTags = {
  application: application
  environment: environment
  costCenter: 'soffort'
  budget: 'under-200-usd'
}

resource virtualNetwork 'Microsoft.Network/virtualNetworks@2025-05-01' = {
  name: 'vnet-soffortbackend-dev-wus2'
  location: location
  tags: commonTags
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.40.0.0/22'
      ]
    }
    subnets: [
      {
        name: 'snet-aks'
        properties: {
          addressPrefix: '10.40.0.0/23'
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
    ]
  }
}

resource aksSubnet 'Microsoft.Network/virtualNetworks/subnets@2025-05-01' existing = {
  parent: virtualNetwork
  name: 'snet-aks'
}

resource ingressPublicIp 'Microsoft.Network/publicIPAddresses@2025-05-01' = {
  name: ingressPublicIpName
  location: location
  zones: [
    '1'
    '2'
    '3'
  ]
  tags: commonTags
  sku: {
    name: 'Standard'
    tier: 'Regional'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
    idleTimeoutInMinutes: 15
    ddosSettings: {
      protectionMode: 'VirtualNetworkInherited'
    }
  }
}

resource outboundPublicIp 'Microsoft.Network/publicIPAddresses@2025-05-01' = {
  name: outboundPublicIpName
  location: location
  zones: [
    '1'
    '2'
    '3'
  ]
  tags: commonTags
  sku: {
    name: 'Standard'
    tier: 'Regional'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
    idleTimeoutInMinutes: 15
    ddosSettings: {
      protectionMode: 'VirtualNetworkInherited'
    }
  }
}

resource clusterIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: 'id-soffortbackend-aks-dev'
  location: location
  tags: commonTags
}

var networkContributorRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '4d97b98b-1d4f-4787-a291-c67834d212e7'
)

resource subnetNetworkContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(aksSubnet.id, clusterIdentity.id, networkContributorRoleId)
  scope: aksSubnet
  properties: {
    principalId: clusterIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: networkContributorRoleId
  }
}

resource ingressIpNetworkContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(ingressPublicIp.id, clusterIdentity.id, networkContributorRoleId)
  scope: ingressPublicIp
  properties: {
    principalId: clusterIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: networkContributorRoleId
  }
}

resource outboundIpNetworkContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(outboundPublicIp.id, clusterIdentity.id, networkContributorRoleId)
  scope: outboundPublicIp
  properties: {
    principalId: clusterIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: networkContributorRoleId
  }
}

resource registry 'Microsoft.ContainerRegistry/registries@2025-11-01' = {
  name: toLower('acrsoffortdev${uniqueString(subscription().id)}')
  location: location
  tags: commonTags
  sku: {
    name: 'Basic'
  }
  properties: {
    adminUserEnabled: false
    anonymousPullEnabled: false
    dataEndpointEnabled: false
    publicNetworkAccess: 'Enabled'
    policies: {
      // Azure permits disabling export only when public network access is also
      // disabled. Development releases use GitHub-hosted runners, so keep the
      // Basic registry public while relying on Entra/OIDC and disabled admin
      // and anonymous access. Production will move builds onto private-origin
      // infrastructure before disabling the registry export policy.
      quarantinePolicy: {
        status: 'disabled'
      }
      retentionPolicy: {
        days: 7
        status: 'disabled'
      }
      trustPolicy: {
        status: 'disabled'
        type: 'Notary'
      }
    }
  }
}

resource cluster 'Microsoft.ContainerService/managedClusters@2025-05-01' = {
  name: clusterName
  location: location
  tags: commonTags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${clusterIdentity.id}': {}
    }
  }
  sku: {
    name: 'Base'
    tier: 'Free'
  }
  properties: {
    kubernetesVersion: kubernetesVersion
    dnsPrefix: 'soffortbackend-dev'
    nodeResourceGroup: nodeResourceGroupName
    disableLocalAccounts: true
    enableRBAC: true
    aadProfile: {
      managed: true
      enableAzureRBAC: true
      tenantID: tenant().tenantId
    }
    apiServerAccessProfile: {
      enablePrivateCluster: true
      enablePrivateClusterPublicFQDN: false
      privateDNSZone: 'system'
    }
    agentPoolProfiles: [
      {
        name: 'system'
        count: 2
        vmSize: nodeVmSize
        osType: 'Linux'
        osSKU: 'AzureLinux'
        osDiskSizeGB: 32
        osDiskType: 'Managed'
        mode: 'System'
        type: 'VirtualMachineScaleSets'
        availabilityZones: [
          '1'
          '2'
        ]
        enableAutoScaling: false
        maxPods: 30
        vnetSubnetID: aksSubnet.id
        nodeLabels: {
          environment: environment
          workload: 'system-and-app'
        }
        upgradeSettings: {
          maxSurge: '1'
          drainTimeoutInMinutes: 30
          nodeSoakDurationInMinutes: 0
        }
      }
    ]
    networkProfile: {
      networkPlugin: 'azure'
      networkPluginMode: 'overlay'
      networkDataplane: 'cilium'
      networkPolicy: 'cilium'
      loadBalancerSku: 'standard'
      outboundType: 'loadBalancer'
      loadBalancerProfile: {
        outboundIPs: {
          publicIPs: [
            {
              id: outboundPublicIp.id
            }
          ]
        }
      }
      podCidr: '10.244.0.0/16'
      serviceCidr: '10.0.0.0/16'
      dnsServiceIP: '10.0.0.10'
    }
    autoUpgradeProfile: {
      upgradeChannel: 'patch'
      nodeOSUpgradeChannel: 'NodeImage'
    }
    oidcIssuerProfile: {
      enabled: true
    }
    securityProfile: {
      workloadIdentity: {
        enabled: true
      }
    }
    storageProfile: {
      diskCSIDriver: {
        enabled: true
      }
      fileCSIDriver: {
        enabled: false
      }
      snapshotController: {
        enabled: false
      }
    }
  }
  dependsOn: [
    subnetNetworkContributor
    ingressIpNetworkContributor
    outboundIpNetworkContributor
  ]
}

var acrPullRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '7f951dda-4ed3-4680-a7ca-43fe172d538d'
)
resource kubeletAcrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, cluster.id, 'kubelet', acrPullRoleId)
  scope: registry
  properties: {
    principalId: cluster.properties.identityProfile.kubeletidentity.objectId
    principalType: 'ServicePrincipal'
    roleDefinitionId: acrPullRoleId
  }
}

var clusterAdminRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b'
)
resource operatorClusterAdmin 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(cluster.id, operatorObjectId, clusterAdminRoleId)
  scope: cluster
  properties: {
    principalId: operatorObjectId
    principalType: 'User'
    roleDefinitionId: clusterAdminRoleId
  }
}

resource releaseIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: 'id-soffortbackend-release-dev'
  location: location
  tags: union(commonTags, {
    purpose: 'github-acr-push-oidc'
  })
}

resource releaseFederation 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2024-11-30' = {
  parent: releaseIdentity
  name: 'github-development-environment'
  properties: {
    issuer: 'https://token.actions.githubusercontent.com'
    subject: 'repo:${repository}:environment:development'
    audiences: [
      'api://AzureADTokenExchange'
    ]
  }
}

var acrPushRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '8311e382-0749-4cb8-b61a-304f252e45ec'
)
resource releaseAcrPush 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, releaseIdentity.id, acrPushRoleId)
  scope: registry
  properties: {
    principalId: releaseIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: acrPushRoleId
  }
}

resource lifecycleIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: 'id-soffortbackend-lifecycle-dev'
  location: location
  tags: union(commonTags, {
    purpose: 'github-aks-start-stop-oidc'
  })
}

resource lifecycleFederation 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2024-11-30' = {
  parent: lifecycleIdentity
  name: 'github-development-environment'
  properties: {
    issuer: 'https://token.actions.githubusercontent.com'
    subject: 'repo:${repository}:environment:development'
    audiences: [
      'api://AzureADTokenExchange'
    ]
  }
}

var contributorRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'b24988ac-6180-42a0-ab88-20f7382dd24c'
)
resource lifecycleClusterContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(cluster.id, lifecycleIdentity.id, contributorRoleId)
  scope: cluster
  properties: {
    principalId: lifecycleIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: contributorRoleId
  }
}

resource fluxExtension 'Microsoft.KubernetesConfiguration/extensions@2024-11-01' = {
  name: 'flux'
  scope: cluster
  properties: {
    extensionType: 'microsoft.flux'
    autoUpgradeMinorVersion: true
    releaseTrain: 'Stable'
    scope: {
      cluster: {
        releaseNamespace: 'flux-system'
      }
    }
  }
}

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
      // The repository is public. HTTPS read access removes a durable Flux SSH
      // secret; all writes still require GitHub OIDC and protected pull requests.
      url: 'https://github.com/${repository}.git'
      provider: 'Generic'
      repositoryRef: {
        branch: 'main'
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
            INGRESS_PUBLIC_IP_NAME: ingressPublicIpName
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
        // The first committed HelmRelease is intentionally suspended until a
        // signed image digest and real identity outputs are available.
        wait: false
        syncIntervalInSeconds: 60
        retryIntervalInSeconds: 60
        timeoutInSeconds: 600
        postBuild: {
          substitute: {
            ACR_LOGIN_SERVER: registry.properties.loginServer
            ENTRA_ISSUER: entraIssuer
            ENTRA_JWKS_URL: entraJwksUrl
            ENTRA_TENANT_ID: entraTenantId
            ENTRA_API_AUDIENCE: entraApiAudience
            ENTRA_VSCODE_CLIENT_ID: entraVscodeClientId
          }
        }
      }
    }
  }
  dependsOn: [
    fluxExtension
    kubeletAcrPull
  ]
}

output clusterName string = cluster.name
output registryName string = registry.name
output registryLoginServer string = registry.properties.loginServer
output ingressIpAddress string = ingressPublicIp.properties.ipAddress
output releaseClientId string = releaseIdentity.properties.clientId
output lifecycleClientId string = lifecycleIdentity.properties.clientId
output fluxConfigurationName string = fluxConfiguration.name
