targetScope = 'resourceGroup'

@description('Infrastructure identity principal ID created by the bootstrap module.')
param principalId string

@description('Infrastructure identity resource ID used to derive a stable role-assignment name.')
param principalResourceId string

resource dnsZone 'Microsoft.Network/dnsZones@2018-05-01' existing = {
  name: 'soffort.com'
}

var dnsZoneContributorRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'befefa01-2a29-4197-83a8-272ff33ce314'
)

resource infrastructureDnsContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dnsZone.id, principalResourceId, dnsZoneContributorRoleId)
  scope: dnsZone
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: dnsZoneContributorRoleId
  }
}

