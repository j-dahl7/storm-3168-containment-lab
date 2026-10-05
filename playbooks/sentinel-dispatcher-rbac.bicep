targetScope = 'resourceGroup'

param expectedSubscriptionId string
param labId string
param workspaceName string
param executorName string
param dispatcherObjectId string
param groupReaderRoleGuid string
param executorInvokerRoleGuid string
param groupReaderAssignmentGuid string
param sentinelReaderAssignmentGuid string
param executorInvokerAssignmentGuid string
@description('Explicit identity of the Microsoft Sentinel/Azure Security Insights enterprise application in this tenant. No Graph lookup or registration is performed.')
param sentinelAutomationObjectId string = ''
param sentinelAutomationAssignmentGuid string = ''
param grantDispatcherPermissions bool = false
param grantSentinelAutomationPermission bool = false

var ownsGroup = toLower(subscription().subscriptionId) == toLower(expectedSubscriptionId) && resourceGroup().tags.?storm3168LabId == labId
var shouldGrant = grantDispatcherPermissions && ownsGroup

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = { name: workspaceName }
resource executor 'Microsoft.Logic/workflows@2019-05-01' existing = { name: executorName }

module definitions './dispatcher-role-definitions.bicep' = if (shouldGrant) {
  name: 'storm3168-dispatch-roles-${labId}'
  scope: subscription()
  params: {
    labId: labId
    resourceGroupId: resourceGroup().id
    groupReaderRoleGuid: groupReaderRoleGuid
    executorInvokerRoleGuid: executorInvokerRoleGuid
  }
}

resource groupReadGrant 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (shouldGrant) {
  name: groupReaderAssignmentGuid
  properties: {
    principalId: dispatcherObjectId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', groupReaderRoleGuid)
    description: 'Lab group ownership read ${labId}'
  }
  dependsOn: [definitions]
}

resource sentinelReadGrant 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (shouldGrant) {
  name: sentinelReaderAssignmentGuid
  scope: workspace
  properties: {
    principalId: dispatcherObjectId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '8d289c81-5878-46d4-8554-54e1e3d8b5cb')
    description: 'Read only lab Sentinel incident evidence ${labId}'
  }
}

resource invokeGrant 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (shouldGrant) {
  name: executorInvokerAssignmentGuid
  scope: executor
  properties: {
    principalId: dispatcherObjectId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', executorInvokerRoleGuid)
    description: 'Invoke only the configured lab executor ${labId}'
  }
  dependsOn: [definitions]
}

resource sentinelAutomationGrant 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (ownsGroup && grantSentinelAutomationPermission) {
  name: sentinelAutomationAssignmentGuid
  properties: {
    principalId: sentinelAutomationObjectId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'f4c81013-99ee-4d62-a7ee-b3f1f648599a')
    description: 'Explicit Sentinel playbook invocation permission on the dedicated lab group ${labId}'
  }
}

output ownershipGatePassed bool = ownsGroup
output groupReaderRoleDefinitionId string = shouldGrant ? subscriptionResourceId('Microsoft.Authorization/roleDefinitions', groupReaderRoleGuid) : ''
output executorInvokerRoleDefinitionId string = shouldGrant ? subscriptionResourceId('Microsoft.Authorization/roleDefinitions', executorInvokerRoleGuid) : ''
output groupReaderRoleAssignmentId string = shouldGrant ? groupReadGrant.id : ''
output sentinelReaderRoleAssignmentId string = shouldGrant ? sentinelReadGrant.id : ''
output executorInvokerRoleAssignmentId string = shouldGrant ? invokeGrant.id : ''
output sentinelAutomationRoleAssignmentId string = ownsGroup && grantSentinelAutomationPermission ? sentinelAutomationGrant.id : ''
