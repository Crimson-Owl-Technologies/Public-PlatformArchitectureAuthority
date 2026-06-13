#Requires -Version 7.0
<#
.SYNOPSIS
    Automates Azure service principal and M365 Graph app registration for PAA onboarding.

.DESCRIPTION
    Replaces the manual 5-step PAA onboarding process. Creates the required Azure service
    principal (Reader + Security Reader), M365 Graph app registration with all required
    application permissions, and optionally a Defender CSPM service principal.

.PARAMETER TenantId
    Azure AD tenant ID to onboard. Mandatory.

.PARAMETER SubscriptionIds
    Specific Azure subscription IDs to grant access to. If omitted, discovers all enabled
    subscriptions in the tenant.

.PARAMETER IncludeLogAnalytics
    If set, prompts for a Log Analytics workspace ID and includes it in the output block.

.PARAMETER IncludeDefenderCspm
    If set, creates a separate Defender CSPM service principal with Security Reader on all
    subscriptions.

.EXAMPLE
    .\Setup-PaaOnboarding.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

.EXAMPLE
    .\Setup-PaaOnboarding.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -SubscriptionIds @("sub-id-1","sub-id-2") `
        -IncludeLogAnalytics `
        -IncludeDefenderCspm
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeLogAnalytics,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDefenderCspm
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

function Write-Step {
    param ([string]$Message)
    Write-Host $Message -ForegroundColor Yellow
}

function Write-Success {
    param ([string]$Message)
    Write-Host $Message -ForegroundColor Green
}

function Write-Warn {
    param ([string]$Message)
    Write-Host "WARNING: $Message" -ForegroundColor DarkYellow
}

function Get-MaskedSecret {
    param ([string]$Secret)
    "$($Secret.Substring(0, [Math]::Min(8, $Secret.Length)))***"
}

function Wait-SpPropagation {
    param (
        [string]$ObjectId,
        [int]$MaxRetries = 12,
        [int]$DelaySec = 5
    )
    for ($i = 1; $i -le $MaxRetries; $i++) {
        $found = Get-AzADServicePrincipal -ObjectId $ObjectId -ErrorAction SilentlyContinue
        if ($found) {
            Write-Host "   SP propagated after $($i * $DelaySec)s" -ForegroundColor Gray
            return
        }
        Write-Host "   Waiting for AAD propagation ($i/$MaxRetries)..." -ForegroundColor Gray
        Start-Sleep -Seconds $DelaySec
    }
    throw "SP $ObjectId did not propagate within $($MaxRetries * $DelaySec)s"
}

# ---------------------------------------------------------------------------
# Step 1 — Dependency check
# ---------------------------------------------------------------------------

Write-Step "[1/5] Checking dependencies..."

$requiredModules = @('Az.Accounts', 'Az.Resources', 'Microsoft.Graph')
$missingModules = @()

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        $missingModules += $module
    }
}

if ($missingModules.Count -gt 0) {
    Write-Host "ERROR: The following PowerShell modules are required but not installed:" -ForegroundColor Red
    $missingModules | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    Write-Host ""
    Write-Host "Install them with:" -ForegroundColor White
    Write-Host "  Install-Module -Name $($missingModules -join ', ') -Scope CurrentUser -Force" -ForegroundColor White
    exit 1
}

Write-Success "  All required modules found: $($requiredModules -join ', ')"

# ---------------------------------------------------------------------------
# Step 2 — Azure service principal
# ---------------------------------------------------------------------------

Write-Step "[2/5] Creating Azure service principal..."

Write-Host "  Connecting to Azure (tenant: $TenantId)..." -ForegroundColor Cyan
Connect-AzAccount -TenantId $TenantId | Out-Null

# Discover subscriptions
if ($SubscriptionIds -and $SubscriptionIds.Count -gt 0) {
    Write-Host "  Using $($SubscriptionIds.Count) specified subscription(s)..." -ForegroundColor Cyan
    $subscriptions = $SubscriptionIds | ForEach-Object {
        Get-AzSubscription -SubscriptionId $_ -TenantId $TenantId
    }
} else {
    Write-Host "  Discovering all enabled subscriptions in tenant..." -ForegroundColor Cyan
    $subscriptions = Get-AzSubscription -TenantId $TenantId |
        Where-Object { $_.State -eq 'Enabled' }
}

if ($subscriptions.Count -eq 0) {
    Write-Host "ERROR: No enabled subscriptions found in tenant $TenantId." -ForegroundColor Red
    exit 1
}

Write-Host "  Found $($subscriptions.Count) subscription(s):" -ForegroundColor Cyan
$subscriptions | ForEach-Object { Write-Host "    - $($_.Name) ($($_.Id))" -ForegroundColor Gray }

# Stable SP name based on tenant ID — idempotent across runs
$azSpName = "PAA-Azure-$($TenantId.Substring(0, 8))"

$readerRoleId = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'       # Reader
$securityReaderRoleId = '39bc4728-0917-49c7-9d2c-d95423bc2eb4' # Security Reader

$azSp = $null
$azSpCreated = $false
try {
    $azSp = Get-AzADServicePrincipal -DisplayName $azSpName -ErrorAction SilentlyContinue
    if ($azSp) {
        Write-Host "  Reusing existing SP: $azSpName" -ForegroundColor Gray
    } else {
        Write-Host "  Creating service principal '$azSpName'..." -ForegroundColor Cyan
        $azSp = New-AzADServicePrincipal -DisplayName $azSpName
        $azSpCreated = $true
        Wait-SpPropagation -ObjectId $azSp.Id
    }

    # Assign Reader + Security Reader on each subscription
    foreach ($sub in $subscriptions) {
        $scope = "/subscriptions/$($sub.Id)"
        Write-Host "    Assigning Reader on $($sub.Name)..." -ForegroundColor Gray
        New-AzRoleAssignment -ObjectId $azSp.Id -RoleDefinitionId $readerRoleId -Scope $scope -ErrorAction SilentlyContinue | Out-Null
        Write-Host "    Assigning Security Reader on $($sub.Name)..." -ForegroundColor Gray
        New-AzRoleAssignment -ObjectId $azSp.Id -RoleDefinitionId $securityReaderRoleId -Scope $scope -ErrorAction SilentlyContinue | Out-Null
    }

    # Generate client secret (2-year expiry)
    $azSecretExpiry = (Get-Date).AddYears(2)
    $azSecret = New-AzADAppCredential -ApplicationId $azSp.AppId -StartDate (Get-Date) -EndDate $azSecretExpiry

    $azAppId = $azSp.AppId
    $azSecretText = $azSecret.SecretText

    Write-Success "  Azure service principal ready: $azSpName (AppId: $azAppId)"
} catch {
    if ($azSpCreated -and $azSp) {
        try { Remove-AzADServicePrincipal -ObjectId $azSp.Id -Force -ErrorAction SilentlyContinue } catch {}
    }
    throw "Azure SP creation failed: $_"
}

# ---------------------------------------------------------------------------
# Step 3 — M365 Graph app registration
# ---------------------------------------------------------------------------

Write-Step "[3/5] Creating M365 Graph app registration..."

Write-Host "  Connecting to Microsoft Graph (tenant: $TenantId)..." -ForegroundColor Cyan
Connect-MgGraph -TenantId $TenantId -Scopes 'Application.ReadWrite.All' | Out-Null

# Stable app name based on tenant ID — idempotent across runs
$m365AppName = "PAA-M365-$($TenantId.Substring(0, 8))"

# All required Graph application permissions (type = Role, not Scope/delegated)
$requiredGraphPermissions = @(
    'Policy.Read.All',
    'RoleManagement.Read.Directory',
    'Directory.Read.All',
    'Application.Read.All',
    'DeviceManagementManagedDevices.Read.All',
    'DeviceManagementConfiguration.Read.All',
    'DeviceManagementApps.Read.All',
    'SecurityEvents.Read.All',
    'Reports.Read.All',
    'Organization.Read.All',
    'IdentityRiskyUser.Read.All',
    'DelegatedPermissionGrant.Read.All',
    'AuditLog.Read.All',
    'UserAuthenticationMethod.Read.All',
    'CrossTenantInformation.ReadBasic.All',
    'SharePointTenantSettings.Read.All',
    'TeamworkDevice.Read.All'
)

Write-Host "  Resolving Microsoft Graph service principal and permission IDs..." -ForegroundColor Cyan

# I3 — Filter by well-known AppId (stable, not display name)
$graphServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" |
    Select-Object -First 1
if (-not $graphServicePrincipal) {
    Write-Host "ERROR: Could not find Microsoft Graph service principal in tenant." -ForegroundColor Red
    exit 1
}

$graphSpId = $graphServicePrincipal.Id
$graphAppId = $graphServicePrincipal.AppId   # Well-known: 00000003-0000-0000-c000-000000000000

# Build the required resource access list
$resourceAccess = @()
foreach ($permName in $requiredGraphPermissions) {
    $appRole = $graphServicePrincipal.AppRoles | Where-Object { $_.Value -eq $permName }
    if (-not $appRole) {
        Write-Warn "  Permission '$permName' not found in Graph app roles — skipping."
        continue
    }
    $resourceAccess += @{
        Id   = $appRole.Id
        Type = 'Role'
    }
}

$requiredResourceAccess = @(
    @{
        ResourceAppId  = $graphAppId
        ResourceAccess = $resourceAccess
    }
)

$m365App = $null
$m365Sp = $null
$m365SpCreated = $false
$consentFailures = @()
try {
    $existingM365App = Get-MgApplication -Filter "displayName eq '$m365AppName'" -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($existingM365App) {
        Write-Host "  Reusing existing app registration: $m365AppName" -ForegroundColor Gray
        $m365App = $existingM365App
    } else {
        Write-Host "  Creating app registration '$m365AppName' with $($resourceAccess.Count) permissions..." -ForegroundColor Cyan
        $m365App = New-MgApplication `
            -DisplayName $m365AppName `
            -RequiredResourceAccess $requiredResourceAccess `
            -SignInAudience 'AzureADMyOrg'
    }

    $existingM365Sp = Get-MgServicePrincipal -Filter "appId eq '$($m365App.AppId)'" -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($existingM365Sp) {
        Write-Host "  Reusing existing service principal for '$m365AppName'..." -ForegroundColor Gray
        $m365Sp = $existingM365Sp
    } else {
        Write-Host "  Creating service principal for '$m365AppName'..." -ForegroundColor Cyan
        $m365Sp = New-MgServicePrincipal -AppId $m365App.AppId
        $m365SpCreated = $true
        Wait-SpPropagation -ObjectId $m365Sp.Id
    }

    # Attempt admin consent for each permission
    Write-Host "  Attempting admin consent for Graph permissions..." -ForegroundColor Cyan

    foreach ($permName in $requiredGraphPermissions) {
        $appRole = $graphServicePrincipal.AppRoles | Where-Object { $_.Value -eq $permName }
        if (-not $appRole) { continue }

        try {
            New-MgServicePrincipalAppRoleAssignment `
                -ServicePrincipalId $m365Sp.Id `
                -PrincipalId $m365Sp.Id `
                -ResourceId $graphSpId `
                -AppRoleId $appRole.Id | Out-Null
            Write-Host "    Consented: $permName" -ForegroundColor Gray
        } catch {
            $consentFailures += $permName
            Write-Warn "  Admin consent failed for '$permName': $($_.Exception.Message)"
        }
    }

    if ($consentFailures.Count -gt 0) {
        Write-Host ""
        Write-Host "  ACTION REQUIRED: The following permissions need manual admin consent in the Azure portal:" -ForegroundColor DarkYellow
        Write-Host "  Portal URL: https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/CallAnAPI/appId/$($m365App.AppId)/isMSAApp/" -ForegroundColor DarkYellow
        $consentFailures | ForEach-Object { Write-Host "    - $_" -ForegroundColor DarkYellow }
        Write-Host ""
    }

    # Generate client secret (2-year expiry)
    $m365SecretExpiry = (Get-Date).AddYears(2)
    $m365SecretParams = @{
        ApplicationId      = $m365App.Id
        PasswordCredential = @{
            DisplayName = 'PAA-Secret'
            EndDateTime = $m365SecretExpiry
        }
    }
    $m365SecretResult = Add-MgApplicationPassword @m365SecretParams

    $m365AppId = $m365App.AppId
    $m365SecretText = $m365SecretResult.SecretText

    Write-Success "  M365 app registration ready: $m365AppName (AppId: $m365AppId)"
} catch {
    if ($m365SpCreated -and $m365Sp) {
        Write-Warning "Rolling back M365 service principal for '$m365AppName'..."
        try { Remove-MgServicePrincipal -ServicePrincipalId $m365Sp.Id -ErrorAction SilentlyContinue } catch {}
    }
    if ($m365App -and -not $existingM365App) {
        Write-Warning "Rolling back M365 app registration '$m365AppName'..."
        Remove-MgApplication -ApplicationId $m365App.Id -ErrorAction SilentlyContinue
    }
    throw "M365 app registration failed: $_"
}

# ---------------------------------------------------------------------------
# Step 4 — Optional Log Analytics
# ---------------------------------------------------------------------------

$logAnalyticsWorkspaceId = $null

Write-Step "[4/5] Log Analytics configuration..."

if ($IncludeLogAnalytics) {
    Write-Host "  Enter your Log Analytics Workspace ID (from Azure portal > Log Analytics workspace > Overview):" -ForegroundColor Cyan
    $logAnalyticsWorkspaceId = Read-Host "  Workspace ID"
    if ([string]::IsNullOrWhiteSpace($logAnalyticsWorkspaceId)) {
        Write-Warn "  No workspace ID provided — Log Analytics will be skipped in output."
        $logAnalyticsWorkspaceId = $null
    } else {
        Write-Success "  Log Analytics workspace ID recorded."
    }
} else {
    Write-Host "  Skipped (use -IncludeLogAnalytics to configure)." -ForegroundColor Gray
}

# ---------------------------------------------------------------------------
# Step 5 — Optional Defender CSPM
# ---------------------------------------------------------------------------

$defenderAppId = $null
$defenderSecretText = $null
$defenderSpName = $null

Write-Step "[5/5] Defender CSPM service principal..."

if ($IncludeDefenderCspm) {
    # Stable name based on tenant ID — idempotent across runs
    $defenderSpName = "PAA-Defender-$($TenantId.Substring(0, 8))"

    $defenderSp = $null
    try {
        $defenderSp = Get-AzADServicePrincipal -DisplayName $defenderSpName -ErrorAction SilentlyContinue
        if ($defenderSp) {
            Write-Host "  Reusing existing Defender CSPM SP: $defenderSpName" -ForegroundColor Gray
        } else {
            Write-Host "  Creating Defender CSPM service principal '$defenderSpName'..." -ForegroundColor Cyan
            $defenderSp = New-AzADServicePrincipal -DisplayName $defenderSpName
            Wait-SpPropagation -ObjectId $defenderSp.Id
        }

        foreach ($sub in $subscriptions) {
            $scope = "/subscriptions/$($sub.Id)"
            Write-Host "    Assigning Security Reader (Defender) on $($sub.Name)..." -ForegroundColor Gray
            New-AzRoleAssignment -ObjectId $defenderSp.Id -RoleDefinitionId $securityReaderRoleId -Scope $scope -ErrorAction SilentlyContinue | Out-Null
        }

        $defenderSecretExpiry = (Get-Date).AddYears(2)
        $defenderSecret = New-AzADAppCredential -ApplicationId $defenderSp.AppId -StartDate (Get-Date) -EndDate $defenderSecretExpiry

        $defenderAppId = $defenderSp.AppId
        $defenderSecretText = $defenderSecret.SecretText

        Write-Success "  Defender CSPM service principal ready: $defenderSpName (AppId: $defenderAppId)"
    } catch {
        if ($defenderSp -and -not (Get-AzADServicePrincipal -DisplayName $defenderSpName -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq $defenderSp.Id })) {
            Write-Warning "Rolling back Defender CSPM SP '$defenderSpName'..."
            Remove-AzADServicePrincipal -ObjectId $defenderSp.Id -Force -ErrorAction SilentlyContinue
        }
        throw "Defender CSPM SP creation failed: $_"
    }
} else {
    Write-Host "  Skipped (use -IncludeDefenderCspm to create Defender CSPM principal)." -ForegroundColor Gray
}

# ---------------------------------------------------------------------------
# Output block — terminal + file
# ---------------------------------------------------------------------------

$outputFileName = "paa-credentials-$($TenantId.Substring(0, 8)).txt"
$outputFilePath = Join-Path -Path $PSScriptRoot -ChildPath $outputFileName

$subscriptionIdList = ($subscriptions | ForEach-Object { $_.Id }) -join ','

$credLines = @()
$credLines += "# ============================================================"
$credLines += "#  PAA Onboarding Credentials"
$credLines += "#  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC' -AsUTC)"
$credLines += "#  Tenant: $TenantId"
$credLines += "# ============================================================"
$credLines += ""
$credLines += "# -- Azure Service Principal --"
$credLines += "AZURE_TENANT_ID=$TenantId"
$credLines += "AZURE_SP_NAME=$azSpName"
$credLines += "AZURE_CLIENT_ID=$azAppId"
$credLines += "AZURE_CLIENT_SECRET=*** see below ***"
$credLines += "AZURE_SUBSCRIPTION_IDS=$subscriptionIdList"
$credLines += ""
$credLines += "# -- M365 / Graph App Registration --"
$credLines += "M365_TENANT_ID=$TenantId"
$credLines += "M365_APP_NAME=$m365AppName"
$credLines += "M365_CLIENT_ID=$m365AppId"
$credLines += "M365_CLIENT_SECRET=*** see below ***"
$credLines += ""

if ($logAnalyticsWorkspaceId) {
    $credLines += "# -- Log Analytics --"
    $credLines += "LOG_ANALYTICS_WORKSPACE_ID=$logAnalyticsWorkspaceId"
    $credLines += ""
}

if ($IncludeDefenderCspm -and $defenderAppId) {
    $credLines += "# -- Defender CSPM Service Principal --"
    $credLines += "DEFENDER_SP_NAME=$defenderSpName"
    $credLines += "DEFENDER_CLIENT_ID=$defenderAppId"
    $credLines += "DEFENDER_CLIENT_SECRET=*** see below ***"
    $credLines += ""
}

$credLines += "# ============================================================"
$credLines += "#  SECRETS — DELETE THIS FILE AFTER USE"
$credLines += "# ============================================================"
$credLines += "AZURE_CLIENT_SECRET=$azSecretText"
$credLines += "M365_CLIENT_SECRET=$m365SecretText"

if ($IncludeDefenderCspm -and $defenderSecretText) {
    $credLines += "DEFENDER_CLIENT_SECRET=$defenderSecretText"
}

$credLines += ""
$credLines += "# ============================================================"
$credLines += "#  PERMISSIONS GRANTED"
$credLines += "# ============================================================"
$credLines += "# Azure SP roles: Reader, Security Reader (on all listed subscriptions)"
$credLines += "# M365 permissions (application/Role):"
$requiredGraphPermissions | ForEach-Object { $credLines += "#   - $_" }

if ($IncludeDefenderCspm) {
    $credLines += "# Defender SP roles: Security Reader (on all listed subscriptions)"
}

$credLines += ""
$credLines += "# ============================================================"
$credLines += "#  NEXT STEPS"
$credLines += "# ============================================================"
$credLines += "# 1. Open PAA app and go to Settings > Integrations"
$credLines += "# 2. Enter Azure credentials (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)"
$credLines += "# 3. Enter M365 credentials (M365_CLIENT_ID, M365_CLIENT_SECRET, M365_TENANT_ID)"

if ($consentFailures.Count -gt 0) {
    $credLines += "# 4. REQUIRED: Grant admin consent for M365 permissions in the Azure portal:"
    $credLines += "#    https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/CallAnAPI/appId/$m365AppId/isMSAApp/"
}

$credLines += "# 5. DELETE THIS FILE: Remove-Item '$outputFileName'"

# Print to terminal (secrets masked)
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  PAA ONBOARDING CREDENTIALS" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Tenant ID              : $TenantId"
Write-Host ""
Write-Host "  Azure Service Principal" -ForegroundColor Cyan
Write-Host "    Name                 : $azSpName"
Write-Host "    Client ID (App ID)   : $azAppId"
Write-Host "    Client Secret        : $(Get-MaskedSecret $azSecretText)"
Write-Host "    Subscriptions        : $subscriptionIdList"
Write-Host ""
Write-Host "  M365 Graph App Registration" -ForegroundColor Cyan
Write-Host "    Name                 : $m365AppName"
Write-Host "    Client ID (App ID)   : $m365AppId"
Write-Host "    Client Secret        : $(Get-MaskedSecret $m365SecretText)"

if ($logAnalyticsWorkspaceId) {
    Write-Host ""
    Write-Host "  Log Analytics" -ForegroundColor Cyan
    Write-Host "    Workspace ID         : $logAnalyticsWorkspaceId"
}

if ($IncludeDefenderCspm -and $defenderAppId) {
    Write-Host ""
    Write-Host "  Defender CSPM Service Principal" -ForegroundColor Cyan
    Write-Host "    Name                 : $defenderSpName"
    Write-Host "    Client ID (App ID)   : $defenderAppId"
    Write-Host "    Client Secret        : $(Get-MaskedSecret $defenderSecretText)"
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Full secrets are written to the credentials file only." -ForegroundColor DarkYellow
Write-Host ""

# Prompt before writing secrets to disk
$writeFile = Read-Host "Write credentials to disk? (recommended — delete after use) [Y/n]"
if ($writeFile -ne 'n' -and $writeFile -ne 'N') {
    $credLines | Out-File -FilePath $outputFilePath -Encoding UTF8

    # Restrict file ACL to current user only
    $acl = Get-Acl $outputFilePath
    $acl.SetAccessRuleProtection($true, $false)
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, 'FullControl', 'Allow')
    $acl.AddAccessRule($rule)
    Set-Acl $outputFilePath $acl

    Write-Host "  Credentials written to: $outputFilePath" -ForegroundColor Green
    Write-Host ""
    Write-Host "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor DarkYellow
    Write-Host "  !!  SECURITY WARNING: DELETE THIS FILE AFTER USE          !!" -ForegroundColor DarkYellow
    Write-Host "  !!  Run: Remove-Item '$outputFileName'                     !!" -ForegroundColor DarkYellow
    Write-Host "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor DarkYellow
    Write-Host ""
} else {
    Write-Host "  Credential file skipped. Copy secrets from terminal output above." -ForegroundColor DarkYellow
    Write-Host ""
}

Write-Success "PAA onboarding complete. All credentials are ready."
