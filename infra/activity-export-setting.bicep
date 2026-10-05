targetScope = 'subscription'
// Internal module only: caller proves exact setting ID absent and workspace tag
// owned. Never deploy this module as a general existing-export updater.
param settingName string
param workspaceId string
resource activityExport 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: settingName
  properties: {
    workspaceId: workspaceId
    logs: [{ category: 'Administrative', enabled: true }]
    metrics: []
  }
}
