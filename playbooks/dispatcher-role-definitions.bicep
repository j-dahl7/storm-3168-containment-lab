targetScope = 'subscription'

// Internal module, deployed only by sentinel-dispatcher-rbac.bicep.
param labId string
param resourceGroupId string
param groupReaderRoleGuid string
param executorInvokerRoleGuid string

resource groupReader 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: groupReaderRoleGuid
  properties: {
    roleName: 'Storm3168 ownership reader ${labId}'
    type: 'CustomRole'
    description: 'Read only the ownership metadata of the dedicated lab group.'
    assignableScopes: [resourceGroupId]
    permissions: [{
      actions: ['Microsoft.Resources/subscriptions/resourceGroups/read']
      notActions: []
      dataActions: []
      notDataActions: []
    }]
  }
}

resource executorInvoker 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: executorInvokerRoleGuid
  properties: {
    roleName: 'Storm3168 executor invoker ${labId}'
    type: 'CustomRole'
    description: 'Read configuration and run a trigger; assign only on the exact guarded executor workflow.'
    assignableScopes: [resourceGroupId]
    permissions: [{
      actions: [
        'Microsoft.Logic/workflows/read'
        'Microsoft.Logic/workflows/triggers/run/action'
      ]
      notActions: []
      dataActions: []
      notDataActions: []
    }]
  }
}
