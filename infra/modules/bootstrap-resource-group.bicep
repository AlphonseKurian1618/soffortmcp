targetScope = 'resourceGroup'

@description('Location for the GitHub infrastructure managed identity.')
param location string

var repository = 'AlphonseKurian1618/soffortmcp'
var commonTags = {
  application: 'soffortbackend'
  environment: 'development'
  purpose: 'github-infrastructure-oidc'
}

resource infrastructureIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: 'id-soffortbackend-infra-dev'
  location: location
  tags: commonTags
}

resource infrastructureFederation 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2024-11-30' = {
  parent: infrastructureIdentity
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
var rbacAdministratorRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'f58310d9-a9f6-439a-9e8d-f62e7b41a168'
)

resource infrastructureContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, infrastructureIdentity.id, contributorRoleId)
  properties: {
    principalId: infrastructureIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: contributorRoleId
  }
}

// This permission is limited to the development resource group. It lets the
// declarative platform grant AcrPull and narrowly scoped lifecycle roles.
resource infrastructureRbacAdministrator 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, infrastructureIdentity.id, rbacAdministratorRoleId)
  properties: {
    principalId: infrastructureIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: rbacAdministratorRoleId
  }
}

output infrastructureClientId string = infrastructureIdentity.properties.clientId
output infrastructurePrincipalId string = infrastructureIdentity.properties.principalId
output infrastructureResourceId string = infrastructureIdentity.id

