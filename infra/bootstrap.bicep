targetScope = 'subscription'

@description('Azure region used by the development resource group and deployment metadata.')
param location string = 'westus2'

@description('Dedicated development resource group.')
param resourceGroupName string = 'rg-soffortbackend-dev-wus2'

@description('Email addresses that receive actual and forecast budget alerts.')
@minLength(1)
param budgetContactEmails array

@description('First day of the current month, generated only when deployment starts.')
param budgetStartDate string = utcNow('yyyy-MM-01')

resource developmentResourceGroup 'Microsoft.Resources/resourceGroups@2024-11-01' = {
  name: resourceGroupName
  location: location
  tags: {
    application: 'soffortbackend'
    environment: 'development'
    costCenter: 'soffort'
    budget: 'under-200-usd'
  }
}

module resourceGroupBootstrap './modules/bootstrap-resource-group.bicep' = {
  name: 'soffortbackend-bootstrap-resource-group'
  scope: developmentResourceGroup
  params: {
    location: location
  }
}

resource developmentBudget 'Microsoft.Consumption/budgets@2024-08-01' = {
  name: 'budget-soffortbackend-dev-monthly'
  properties: {
    amount: 200
    category: 'Cost'
    timeGrain: 'Monthly'
    timePeriod: {
      startDate: budgetStartDate
      endDate: '2036-12-31'
    }
    notifications: {
      actual150: {
        enabled: true
        operator: 'GreaterThanOrEqualTo'
        threshold: 75
        thresholdType: 'Actual'
        contactEmails: budgetContactEmails
      }
      forecast180: {
        enabled: true
        operator: 'GreaterThanOrEqualTo'
        threshold: 90
        thresholdType: 'Forecasted'
        contactEmails: budgetContactEmails
      }
      actual195: {
        enabled: true
        operator: 'GreaterThanOrEqualTo'
        threshold: json('97.5')
        thresholdType: 'Actual'
        contactEmails: budgetContactEmails
      }
    }
  }
}

output resourceGroupName string = developmentResourceGroup.name
output infrastructureClientId string = resourceGroupBootstrap.outputs.infrastructureClientId
output infrastructurePrincipalId string = resourceGroupBootstrap.outputs.infrastructurePrincipalId
