targetScope = 'subscription'

// Internal module: deploy only through responder-rbac.bicep after its RG tag
// check and the caller's exact-ID no-adoption preflight.
param resourceGroupId string
param labId string
param roleGuid string

resource responderRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: roleGuid
  properties: {
    roleName: 'Storm3168 bounded role removal ${labId}'
    description: 'Lab ${labId}: read ownership/assignments and conditionally remove the configured actor role. No effective-access guarantee.'
    type: 'CustomRole'
    assignableScopes: [resourceGroupId]
    permissions: [{
      actions: [
        'Microsoft.Resources/subscriptions/resourceGroups/read'
        'Microsoft.Authorization/roleAssignments/read'
        'Microsoft.Authorization/roleAssignments/delete'
      ]
      notActions: []
      dataActions: []
      notDataActions: []
    }]
  }
}
