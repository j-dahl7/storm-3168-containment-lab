targetScope = 'resourceGroup'

@description('Explicit subscription UUID. The deployment wrapper must verify it against the selected subscription.')
@minLength(36)
@maxLength(36)
param expectedSubscriptionId string

@description('UUID already recorded in the existing dedicated resource group storm3168LabId tag. Never stamp this tag onto an existing unrelated group.')
@minLength(36)
@maxLength(36)
param labId string

param location string

@minLength(3)
@maxLength(24)
param storageAccountName string

@minLength(4)
@maxLength(63)
param workspaceName string

@description('Decimal GB as a string because Bicep has no float parameter type. This ingestion quota is not an enforced spending cap.')
@allowed(['0.1', '0.25', '0.5', '1'])
param workspaceDailyQuotaGb string = '0.1'

@description('Explicit opt-in. No analytics rules, connectors or automation are installed by this switch.')
param enableSentinel bool = false

var ownsGroup = toLower(subscription().subscriptionId) == toLower(expectedSubscriptionId) && resourceGroup().tags.?storm3168LabId == labId
var labTags = {
  storm3168LabId: labId
  purpose: 'storm3168-containment-lab'
  evidenceStatus: 'not_tested'
}

// ARM deployments are upserts. The caller MUST check both resource IDs return 404
// before initial deployment; this tag gate alone is not an adoption safeguard.
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = if (ownsGroup) {
  name: storageAccountName
  location: location
  tags: labTags
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    accessTier: 'Hot'
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      bypass: 'None'
      defaultAction: 'Deny'
      ipRules: []
      virtualNetworkRules: []
    }
  }
}

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = if (ownsGroup) {
  name: workspaceName
  location: location
  tags: labTags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
    workspaceCapping: { dailyQuotaGb: json(workspaceDailyQuotaGb) }
  }
}

resource sentinel 'Microsoft.SecurityInsights/onboardingStates@2024-03-01' = if (ownsGroup && enableSentinel) {
  scope: workspace
  name: 'default'
  properties: { customerManagedKey: false }
}

output ownershipGatePassed bool = ownsGroup
output storageResourceId string = ownsGroup ? storage.id : ''
output workspaceResourceId string = ownsGroup ? workspace.id : ''
output sentinelRequested bool = enableSentinel
