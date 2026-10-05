targetScope = 'resourceGroup'

param expectedSubscriptionId string
param labId string
param location string
param workspaceName string
param analyticRuleId string
param dispatcherName string
param connectionName string
param executorName string
param actorObjectId string
param targetRoleAssignmentId string
param targetRoleDefinitionId string
param targetRoleScope string
@description('Fresh trial UTC lower bound. Old incidents and replayed trigger items are rejected.')
param notBeforeUtc string
@description('Trial UTC end, at most two hours after notBeforeUtc. Renew only for a separately reviewed trial.')
param notAfterUtc string
param dispatchEnabled bool = false
param expectedExecutorDryRun bool = true
@allowed(['', 'INVOKE_CONFIGURED_LAB_EXECUTOR'])
param dispatchConfirmation string = ''

var ownsGroup = toLower(subscription().subscriptionId) == toLower(expectedSubscriptionId) && resourceGroup().tags.?storm3168LabId == labId
var workspaceId = resourceId('Microsoft.OperationalInsights/workspaces', workspaceName)
var managedApiId = subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')

resource connection 'Microsoft.Web/connections@2016-06-01' = if (ownsGroup) {
  name: connectionName
  location: location
  tags: { storm3168LabId: labId }
  // Microsoft Sentinel's official Consumption template uses these newer fields.
  #disable-next-line BCP187
  kind: 'V1'
  properties: any({
    displayName: connectionName
    customParameterValues: {}
    parameterValueType: 'Alternative'
    api: { id: managedApiId }
  })
}

resource dispatcher 'Microsoft.Logic/workflows@2019-05-01' = if (ownsGroup) {
  name: dispatcherName
  location: location
  identity: { type: 'SystemAssigned' }
  tags: {
    storm3168LabId: labId
    LogicAppsCategory: 'security'
    purpose: 'storm3168-sentinel-dispatcher'
  }
  properties: {
    state: 'Disabled'
    definition: loadJsonContent('./sentinel-dispatcher.workflow.json')
    parameters: {
      '$connections': {
        value: {
          azuresentinel: {
            connectionId: connection.id
            connectionName: connectionName
            id: managedApiId
            connectionProperties: { authentication: { type: 'ManagedServiceIdentity' } }
          }
        }
      }
      expectedSubscriptionId: { value: expectedSubscriptionId }
      labId: { value: labId }
      resourceGroupId: { value: resourceGroup().id }
      workspaceResourceId: { value: workspaceId }
      analyticRuleResourceId: { value: '${workspaceId}/providers/Microsoft.SecurityInsights/alertRules/${analyticRuleId}' }
      actorObjectId: { value: actorObjectId }
      executorResourceId: { value: resourceId('Microsoft.Logic/workflows', executorName) }
      targetRoleAssignmentId: { value: targetRoleAssignmentId }
      targetRoleDefinitionId: { value: targetRoleDefinitionId }
      targetRoleScope: { value: targetRoleScope }
      notBeforeUtc: { value: notBeforeUtc }
      notAfterUtc: { value: notAfterUtc }
      dispatchEnabled: { value: dispatchEnabled }
      expectedExecutorDryRun: { value: expectedExecutorDryRun }
      dispatchConfirmation: { value: dispatchConfirmation }
    }
  }
}

output ownershipGatePassed bool = ownsGroup
output dispatcherResourceId string = ownsGroup ? dispatcher.id : ''
output dispatcherObjectId string = ownsGroup ? dispatcher!.identity.principalId : ''
output connectionResourceId string = ownsGroup ? connection.id : ''
