targetScope = 'resourceGroup'

@description('Static AKS ingress IPv4 address published at the zone apex.')
param ingressIpAddress string

resource dnsZone 'Microsoft.Network/dnsZones@2018-05-01' existing = {
  name: 'soffort.com'
}

resource apexRecord 'Microsoft.Network/dnsZones/A@2018-05-01' = {
  parent: dnsZone
  name: '@'
  properties: {
    TTL: 300
    ARecords: [
      {
        ipv4Address: ingressIpAddress
      }
    ]
  }
}

