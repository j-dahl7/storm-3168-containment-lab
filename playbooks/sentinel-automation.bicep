targetScope = 'resourceGroup'

param expectedSubscriptionId string
param labId string
param workspaceName string
param analyticRuleId string
param dispatcherName string
@description('Fresh UUID recorded in the private manifest; exact new resource ID must return 404 before deployment.')
param automationRuleId string
@description('Explicit UTC expiry for the bounded lab session, e.g. 2026-10-05T18:00:00Z. Do not leave automation indefinitely armed.')
param expiresAtUtc string
param enableAutomationRule bool = false

var ownsGroup = toLower(subscription().subscriptionId) == toLower(expectedSubscriptionId) && resourceGroup().tags.?storm3168LabId == labId
resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = { name: workspaceName }

resource binding 'Microsoft.SecurityInsights/automationRules@2025-09-01' = if (ownsGroup) {
  scope: workspace
  name: automationRuleId
  properties: {
    displayName: 'LAB Storm3168 guarded dispatcher ${labId}'
    order: 100
    triggeringLogic: {
      isEnabled: enableAutomationRule
      triggersOn: 'Incidents'
      triggersWhen: 'Created'
      expirationTimeUtc: expiresAtUtc
      conditions: [{
        conditionType: 'Property'
        conditionProperties: {
          propertyName: 'IncidentRelatedAnalyticRuleIds'
          operator: 'Contains'
          propertyValues: ['${workspace.id}/providers/Microsoft.SecurityInsights/alertRules/${analyticRuleId}']
        }
      }]
    }
    actions: [{
      order: 1
      actionType: 'RunPlaybook'
      actionConfiguration: {
        logicAppResourceId: resourceId('Microsoft.Logic/workflows', dispatcherName)
        tenantId: tenant().tenantId
      }
    }]
  }
}

output ownershipGatePassed bool = ownsGroup
output automationRuleResourceId string = ownsGroup ? binding.id : ''
