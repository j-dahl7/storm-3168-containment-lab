targetScope = 'resourceGroup'

@description('Explicit selected subscription; the wrapper also verifies the tenant.')
param expectedSubscriptionId string
param labId string
param workspaceName string
@description('Fresh UUID recorded before PUT; an existing diagnostic setting is never adopted.')
param exportId string
@description('Explicit opt-in to subscription-wide Administrative activity export. Default false.')
param enableExport bool = false

// The wrapper verifies the exact workspace tag before mutation; Bicep cannot use
// an existing workspace's runtime tags as a resource-deployment if condition.
var ownsTargets = toLower(subscription().subscriptionId) == toLower(expectedSubscriptionId) && resourceGroup().tags.?storm3168LabId == labId
var settingName = 'storm3168-activity-${labId}-${exportId}'

// A separate setting; no Entra exports, no existing setting updates, no new
// workspace, no resource-group filtering (this category is subscription-wide).
// The guarded wrapper must prove the exact setting ID absent before deployment.
module activityExport './activity-export-setting.bicep' = if (enableExport && ownsTargets) {
  name: 'storm3168-export-${exportId}'
  scope: subscription()
  params: {
    settingName: settingName
    workspaceId: resourceId('Microsoft.OperationalInsights/workspaces', workspaceName)
  }
}

output ownershipGatePassed bool = ownsTargets
output diagnosticSettingId string = enableExport && ownsTargets ? subscriptionResourceId('Microsoft.Insights/diagnosticSettings', settingName) : ''
output subscriptionWideAdministrativeExport bool = enableExport && ownsTargets
