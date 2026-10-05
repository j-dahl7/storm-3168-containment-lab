targetScope = 'resourceGroup'

@minLength(36)
@maxLength(36)
param expectedSubscriptionId string
@minLength(36)
@maxLength(36)
param labId string
@description('System-assigned identity object ID returned by the separately deployed workflow.')
@minLength(36)
@maxLength(36)
param responderObjectId string
@description('Only this lab service principal may have a role removed.')
@minLength(36)
@maxLength(36)
param actorObjectId string
@description('Full subscription-qualified target role definition resource ID, not a role display name.')
param targetRoleDefinitionId string
@description('Fresh UUID recorded in the private manifest before initial deployment; GET its exact subscription role-definition ID must return 404.')
@minLength(36)
@maxLength(36)
param responderRoleDefinitionGuid string
@description('Fresh UUID recorded in the private manifest before initial deployment; GET its exact lab-group role-assignment ID must return 404.')
@minLength(36)
@maxLength(36)
param responderRoleAssignmentGuid string
@description('Must be explicitly true. Does not enable or invoke the workflow.')
param grantResponderPermissions bool = false

var ownsGroup = toLower(subscription().subscriptionId) == toLower(expectedSubscriptionId) && resourceGroup().tags.?storm3168LabId == labId
var shouldGrant = grantResponderPermissions && ownsGroup
var roleGuid = last(split(targetRoleDefinitionId, '/'))
var responderRoleGuid = responderRoleDefinitionGuid
var responderRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', responderRoleGuid)
var grantGuid = responderRoleAssignmentGuid
var removalCondition = '((!(ActionMatches{\'Microsoft.Authorization/roleAssignments/delete\'})) OR ((@Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {${roleGuid}}) AND (@Resource[Microsoft.Authorization/roleAssignments:PrincipalId] ForAnyOfAnyValues:GuidEquals {${actorObjectId}}) AND (@Resource[Microsoft.Authorization/roleAssignments:PrincipalType] StringEqualsIgnoreCase \'ServicePrincipal\')))'

// A custom role definition is subscription-level metadata. Its sole assignable
// scope is this lab group; only this explicit template creates the role or grant.
module roleDefinition './responder-role-definition.bicep' = if (shouldGrant) {
  name: 'storm3168-role-${labId}'
  scope: subscription()
  params: {
    resourceGroupId: resourceGroup().id
    labId: labId
    roleGuid: responderRoleGuid
  }
}

resource responderGrant 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (shouldGrant) {
  name: grantGuid
  properties: {
    principalId: responderObjectId
    principalType: 'ServicePrincipal'
    roleDefinitionId: responderRoleId
    conditionVersion: '2.0'
    condition: removalCondition
    description: 'Explicit lab-only responder grant ${labId}'
  }
  dependsOn: [roleDefinition]
}

output ownershipGatePassed bool = ownsGroup
output responderRoleDefinitionId string = shouldGrant ? responderRoleId : ''
output responderRoleAssignmentId string = shouldGrant ? responderGrant.id : ''
