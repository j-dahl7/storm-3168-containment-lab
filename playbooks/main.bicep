targetScope = 'resourceGroup'

@minLength(36)
@maxLength(36)
param expectedSubscriptionId string
@minLength(36)
@maxLength(36)
param labId string
param location string
param workflowName string
@minLength(36)
@maxLength(36)
param actorObjectId string
param targetRoleAssignmentId string
param targetRoleDefinitionId string
param targetRoleScope string
@description('No deletion when true. Changing this never enables the workflow.')
param dryRun bool = true
@allowed(['', 'REMOVE_CONFIGURED_LAB_ROLE'])
param executionConfirmation string = ''

var ownsGroup = toLower(subscription().subscriptionId) == toLower(expectedSubscriptionId) && resourceGroup().tags.?storm3168LabId == labId

resource workflow 'Microsoft.Logic/workflows@2019-05-01' = if (ownsGroup) {
  name: workflowName
  location: location
  tags: {
    storm3168LabId: labId
    purpose: 'storm3168-containment-lab'
    evidenceStatus: 'not_tested'
  }
  identity: { type: 'SystemAssigned' }
  properties: {
    state: 'Disabled'
    definition: loadJsonContent('./workflow.json')
    // sasAuthenticationPolicy is documented for Consumption workflows, but is
    // newer than this API version's published Bicep type definition.
    accessControl: any({
      triggers: {
        allowedCallerIpAddresses: []
        sasAuthenticationPolicy: { state: 'Disabled' }
      }
    })
    parameters: {
      expectedSubscriptionId: { value: expectedSubscriptionId }
      labId: { value: labId }
      resourceGroupId: { value: resourceGroup().id }
      actorObjectId: { value: actorObjectId }
      targetRoleAssignmentId: { value: targetRoleAssignmentId }
      targetRoleDefinitionId: { value: targetRoleDefinitionId }
      targetRoleScope: { value: targetRoleScope }
      dryRun: { value: dryRun }
      executionConfirmation: { value: executionConfirmation }
    }
  }
}

output ownershipGatePassed bool = ownsGroup
output workflowResourceId string = ownsGroup ? workflow.id : ''
output responderObjectId string = ownsGroup ? workflow!.identity.principalId : ''
// Deliberately no listCallbackUrl(), callback URL, key, token or SAS output.
