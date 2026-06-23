#Requires -Version 7.0
<#
.SYNOPSIS
    Automates Azure service principal and M365 Graph app registration for PAA onboarding.

.DESCRIPTION
    Replaces the manual 5-step PAA onboarding process. Creates the required Azure service
    principal (Reader + Security Reader + Cost Management Reader), M365 Graph app registration
    with all required application permissions, and optionally a Defender CSPM service principal.

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

.EXAMPLE
    # Re-apply permissions only (existing apps, no new secrets) — e.g. to grant newly-added R-613
    # SharePoint / Power Platform / Global Reader permissions to an already-onboarded tenant:
    .\Setup-PaaOnboarding.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -PermissionsOnly
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
    [switch]$IncludeDefenderCspm,

    # Re-apply permissions/roles/registrations to EXISTING service principals only. Does NOT create
    # apps/SPs and does NOT generate any secret or credentials file. Use to grant newly-added
    # permissions (e.g. R-613 SharePoint Sites.FullControl.All, the Power Platform management-app
    # registration, Global Reader) to tenants onboarded before those were part of the script.
    [Parameter(Mandatory = $false)]
    [switch]$PermissionsOnly
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

# R-619 — turns an Az-created service principal into a self-managing Graph app:
# grants it the self-scoped Application.ReadWrite.OwnedBy Graph app role (admin-consented)
# and makes it the owner of its own app registration, so PAA can later replace the
# bootstrap secret with a self-rotating certificate. Mirrors the M365 app handling exactly.
# Requires an active Connect-MgGraph session. Appends any consent failure to the
# referenced collection. Returns nothing.
function Set-SelfManagedCertBootstrap {
    param (
        [Parameter(Mandatory = $true)][string]$AppId,            # appId / clientId of the Az-created SP
        [Parameter(Mandatory = $true)][string]$Label,            # friendly name for log lines
        [Parameter(Mandatory = $true)]$GraphServicePrincipal,    # resolved Microsoft Graph SP object
        [Parameter(Mandatory = $true)][ref]$ConsentFailures      # collection to append failures to
    )

    # Resolve the app + its service principal in Graph by appId (stable, not display name).
    $graphApp = Get-MgApplication -Filter "appId eq '$AppId'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $graphApp) {
        Write-Warn "  Could not resolve Graph application for $Label (appId $AppId) — skipping OwnedBy/self-ownership."
        $ConsentFailures.Value += "Application.ReadWrite.OwnedBy ($Label)"
        return
    }
    $graphSp = Get-MgServicePrincipal -Filter "appId eq '$AppId'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $graphSp) {
        Write-Warn "  Could not resolve Graph service principal for $Label (appId $AppId) — skipping OwnedBy/self-ownership."
        $ConsentFailures.Value += "Application.ReadWrite.OwnedBy ($Label)"
        return
    }

    # Add Application.ReadWrite.OwnedBy to the app's requiredResourceAccess (Graph resource),
    # preserving any existing entries.
    $ownedByRole = $GraphServicePrincipal.AppRoles | Where-Object { $_.Value -eq 'Application.ReadWrite.OwnedBy' }
    if (-not $ownedByRole) {
        Write-Warn "  'Application.ReadWrite.OwnedBy' app role not found on Microsoft Graph SP — skipping for $Label."
        $ConsentFailures.Value += "Application.ReadWrite.OwnedBy ($Label)"
        return
    }
    $graphResourceAppId = $GraphServicePrincipal.AppId   # 00000003-0000-0000-c000-000000000000

    $existingRra = @()
    if ($graphApp.RequiredResourceAccess) { $existingRra = @($graphApp.RequiredResourceAccess) }

    $graphEntry = $existingRra | Where-Object { $_.ResourceAppId -eq $graphResourceAppId } | Select-Object -First 1
    if ($graphEntry) {
        $alreadyHas = $graphEntry.ResourceAccess | Where-Object { $_.Id -eq $ownedByRole.Id }
        if (-not $alreadyHas) {
            $graphEntry.ResourceAccess += @{ Id = $ownedByRole.Id; Type = 'Role' }
        }
    } else {
        $existingRra += @{
            ResourceAppId  = $graphResourceAppId
            ResourceAccess = @(@{ Id = $ownedByRole.Id; Type = 'Role' })
        }
    }
    try {
        Update-MgApplication -ApplicationId $graphApp.Id -RequiredResourceAccess $existingRra -ErrorAction Stop
        Write-Host "    [$Label] Added Application.ReadWrite.OwnedBy to requiredResourceAccess" -ForegroundColor Gray
    } catch {
        Write-Warn "  [$Label] Could not update requiredResourceAccess: $($_.Exception.Message)"
        $ConsentFailures.Value += "Application.ReadWrite.OwnedBy manifest ($Label)"
    }

    # Grant + admin-consent the app role to the SP.
    try {
        New-MgServicePrincipalAppRoleAssignment `
            -ServicePrincipalId $graphSp.Id `
            -PrincipalId $graphSp.Id `
            -ResourceId $GraphServicePrincipal.Id `
            -AppRoleId $ownedByRole.Id `
            -ErrorAction Stop | Out-Null
        Write-Host "    [$Label] Consented: Application.ReadWrite.OwnedBy" -ForegroundColor Gray
    } catch {
        if ($_.Exception.Message -match 'already exists') {
            Write-Warn "  [$Label] 'Application.ReadWrite.OwnedBy' role already assigned (re-run); skipping."
        } else {
            $ConsentFailures.Value += "Application.ReadWrite.OwnedBy ($Label)"
            Write-Warn "  [$Label] Admin consent failed for 'Application.ReadWrite.OwnedBy': $($_.Exception.Message)"
        }
    }

    # Self-ownership — Application.ReadWrite.OwnedBy only applies to apps the SP owns.
    try {
        $ownerRef = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($graphSp.Id)" }
        New-MgApplicationOwnerByRef -ApplicationId $graphApp.Id -BodyParameter $ownerRef -ErrorAction Stop
        Write-Host "    [$Label] Set service principal as owner of its own app registration" -ForegroundColor Gray
    } catch {
        Write-Warn "  [$Label] Could not set self-ownership (may already be owner): $($_.Exception.Message)"
    }
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
$costManagementReaderRoleId = '72fafb9e-0641-4937-9268-a91bfd8191a3' # Cost Management Reader (cost analytics — Reader's */read does NOT cover the CostManagement query action)

$azSp = $null
$azSpCreated = $false
try {
    $azSp = Get-AzADServicePrincipal -DisplayName $azSpName -ErrorAction SilentlyContinue
    if ($azSp) {
        Write-Host "  Reusing existing SP: $azSpName" -ForegroundColor Gray
    } elseif ($PermissionsOnly) {
        throw "PermissionsOnly: Azure SP '$azSpName' not found. Run without -PermissionsOnly to create it."
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
        Write-Host "    Assigning Cost Management Reader on $($sub.Name)..." -ForegroundColor Gray
        New-AzRoleAssignment -ObjectId $azSp.Id -RoleDefinitionId $costManagementReaderRoleId -Scope $scope -ErrorAction SilentlyContinue | Out-Null
    }

    $azAppId = $azSp.AppId

    # Bootstrap-only secret: PAA discards it after provisioning a self-rotating certificate (R-619).
    # 7-day expiry — NOT a long-lived credential. Skipped in -PermissionsOnly (no new credentials).
    if (-not $PermissionsOnly) {
        $azSecretExpiry = (Get-Date).AddDays(7)
        $azSecret = New-AzADAppCredential -ApplicationId $azSp.AppId -StartDate (Get-Date) -EndDate $azSecretExpiry
        $azSecretText = $azSecret.SecretText
    }

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
# Scopes needed:
#  - Application.ReadWrite.All        : create the app registration + set self-ownership
#  - AppRoleAssignment.ReadWrite.All  : grant admin consent (create app-role assignments)
#  - RoleManagement.ReadWrite.Directory: assign the Global Reader directory role
# Without AppRoleAssignment.ReadWrite.All every permission grant returns 403
# Authorization_RequestDenied. Re-running triggers a one-time consent prompt for these scopes.
Connect-MgGraph -TenantId $TenantId -Scopes 'Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All','RoleManagement.ReadWrite.Directory' | Out-Null

# Stable app name based on tenant ID — idempotent across runs
$m365AppName = "PAA-M365-$($TenantId.Substring(0, 8))"

# Required Graph application permissions (type = Role). Least-privilege set, cross-checked
# against actual collector/ZeroTrust endpoint usage. All read-only EXCEPT
# Application.ReadWrite.OwnedBy, which is self-scoped (manages only this app's own credential,
# per R-618). Directory.Read.All is the umbrella for directory-object reads (applications,
# servicePrincipals, organization, groups, users, directoryRoles, domains) — narrower roles it
# already covers (Application.Read.All / Organization.Read.All / Group.Read.All) are NOT granted.
$requiredGraphPermissions = @(
    'Directory.Read.All',                    # Directory objects: roles, users, SPs, apps, groups, org, domains
    'Policy.Read.All',                       # CA / auth-method / authorization / cross-tenant-access / app-mgmt policies
    'RoleManagement.Read.Directory',         # PIM schedules + role management policies
    'AccessReview.Read.All',                 # Access review definitions/instances (P2)
    'DelegatedAdminRelationship.Read.All',   # GDAP partner relationships
    'DelegatedPermissionGrant.Read.All',     # OAuth2 delegated grants (oauth2PermissionGrants)
    'IdentityRiskyUser.Read.All',            # Identity Protection risky users (P2)
    'AuditLog.Read.All',                     # signInActivity on guest users
    'Reports.Read.All',                      # assigned-but-inactive M365 license detection (R-610); degrades gracefully if absent
    'DeviceManagementManagedDevices.Read.All',
    'DeviceManagementConfiguration.Read.All',
    'DeviceManagementApps.Read.All',
    'SecurityEvents.Read.All',               # Defender alerts + secure score + DfO beta policies
    'SecurityIncident.Read.All',             # Defender incidents (CollectIncidentSummaryAsync)
    'SharePointTenantSettings.Read.All',     # SharePoint / OneDrive admin settings
    'Application.ReadWrite.OwnedBy'          # R-618: self-scoped cert bootstrap/rotation (this app only)
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

# Office 365 Exchange Online (for R-613 PowerShell collection) — Exchange.ManageAsApp app role.
$exoAppId = '00000002-0000-0ff1-ce00-000000000000'
$exoSp = Get-MgServicePrincipal -Filter "appId eq '$exoAppId'" | Select-Object -First 1
$exoResourceAccess = @()
if ($exoSp) {
    $exoRole = $exoSp.AppRoles | Where-Object { $_.Value -eq 'Exchange.ManageAsApp' }
    if ($exoRole) {
        $exoResourceAccess += @{ Id = $exoRole.Id; Type = 'Role' }
    } else {
        Write-Warn "  'Exchange.ManageAsApp' app role not found on Exchange Online SP — skipping."
    }
} else {
    Write-Warn "  Office 365 Exchange Online service principal not found in tenant — skipping Exchange.ManageAsApp."
}

# SharePoint Online (for R-613 PnP collection — Get-PnPTenant / Get-PnPTenantSite) — Sites.FullControl.All app role.
$spoAppId = '00000003-0000-0ff1-ce00-000000000000'
$spoSp = Get-MgServicePrincipal -Filter "appId eq '$spoAppId'" | Select-Object -First 1
$spoResourceAccess = @()
if ($spoSp) {
    $spoRole = $spoSp.AppRoles | Where-Object { $_.Value -eq 'Sites.FullControl.All' }
    if ($spoRole) {
        $spoResourceAccess += @{ Id = $spoRole.Id; Type = 'Role' }
    } else {
        Write-Warn "  'Sites.FullControl.All' app role not found on SharePoint Online SP — skipping."
    }
} else {
    Write-Warn "  SharePoint Online service principal not found in tenant — skipping Sites.FullControl.All."
}

# Power BI Service (for CIS Section 9 Power BI / Fabric checks) — Tenant.Read.All app role.
# NOTE: this grant is necessary but NOT sufficient — a Power BI/Fabric Service Admin must ALSO enable
# "Service principals can use read-only Power BI admin APIs" in the Power BI admin portal (Tenant settings).
$pbiAppId = '00000009-0000-0000-c000-000000000000'
$pbiSp = Get-MgServicePrincipal -Filter "appId eq '$pbiAppId'" | Select-Object -First 1
$pbiResourceAccess = @()
if ($pbiSp) {
    $pbiRole = $pbiSp.AppRoles | Where-Object { $_.Value -eq 'Tenant.Read.All' }
    if ($pbiRole) {
        $pbiResourceAccess += @{ Id = $pbiRole.Id; Type = 'Role' }
    } else {
        Write-Warn "  'Tenant.Read.All' app role not found on Power BI Service SP — skipping."
    }
} else {
    Write-Warn "  Power BI Service service principal not found in tenant — skipping Tenant.Read.All."
}

$requiredResourceAccess = @(
    @{
        ResourceAppId  = $graphAppId
        ResourceAccess = $resourceAccess
    }
)
if ($exoResourceAccess.Count -gt 0) {
    $requiredResourceAccess += @{ ResourceAppId = $exoAppId; ResourceAccess = $exoResourceAccess }
}
if ($spoResourceAccess.Count -gt 0) {
    $requiredResourceAccess += @{ ResourceAppId = $spoAppId; ResourceAccess = $spoResourceAccess }
}
if ($pbiResourceAccess.Count -gt 0) {
    $requiredResourceAccess += @{ ResourceAppId = $pbiAppId; ResourceAccess = $pbiResourceAccess }
}

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
        if ($PermissionsOnly) {
            # Ensure the manifest lists the (possibly newly-added) required resource access so the
            # consents below have a declared permission to bind to. Idempotent / additive.
            try {
                Update-MgApplication -ApplicationId $m365App.Id -RequiredResourceAccess $requiredResourceAccess -ErrorAction Stop
                Write-Host "    Updated app manifest with current required permissions" -ForegroundColor Gray
            } catch {
                Write-Warn "  Could not update app manifest (continuing — consents are granted directly): $($_.Exception.Message)"
            }
        }
    } elseif ($PermissionsOnly) {
        throw "PermissionsOnly: M365 app registration '$m365AppName' not found. Run without -PermissionsOnly to create it."
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
    } elseif ($PermissionsOnly) {
        throw "PermissionsOnly: service principal for '$m365AppName' not found. Run without -PermissionsOnly to create it."
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
                -AppRoleId $appRole.Id `
                -ErrorAction Stop | Out-Null
            Write-Host "    Consented: $permName" -ForegroundColor Gray
        } catch {
            $consentFailures += $permName
            Write-Warn "  Admin consent failed for '$permName': $($_.Exception.Message)"
        }
    }

    if ($exoSp -and $exoResourceAccess.Count -gt 0) {
        try {
            New-MgServicePrincipalAppRoleAssignment `
                -ServicePrincipalId $m365Sp.Id `
                -PrincipalId $m365Sp.Id `
                -ResourceId $exoSp.Id `
                -AppRoleId $exoResourceAccess[0].Id `
                -ErrorAction Stop | Out-Null
            Write-Host "    Consented: Exchange.ManageAsApp" -ForegroundColor Gray
        } catch {
            $consentFailures += 'Exchange.ManageAsApp'
            Write-Warn "  Admin consent failed for 'Exchange.ManageAsApp': $($_.Exception.Message)"
        }
    }

    if ($spoSp -and $spoResourceAccess.Count -gt 0) {
        try {
            New-MgServicePrincipalAppRoleAssignment `
                -ServicePrincipalId $m365Sp.Id `
                -PrincipalId $m365Sp.Id `
                -ResourceId $spoSp.Id `
                -AppRoleId $spoResourceAccess[0].Id `
                -ErrorAction Stop | Out-Null
            Write-Host "    Consented: Sites.FullControl.All (SharePoint)" -ForegroundColor Gray
        } catch {
            $consentFailures += 'Sites.FullControl.All'
            Write-Warn "  Admin consent failed for 'Sites.FullControl.All': $($_.Exception.Message)"
        }
    }

    if ($pbiSp -and $pbiResourceAccess.Count -gt 0) {
        try {
            New-MgServicePrincipalAppRoleAssignment `
                -ServicePrincipalId $m365Sp.Id `
                -PrincipalId $m365Sp.Id `
                -ResourceId $pbiSp.Id `
                -AppRoleId $pbiResourceAccess[0].Id `
                -ErrorAction Stop | Out-Null
            Write-Host "    Consented: Tenant.Read.All (Power BI)" -ForegroundColor Gray
        } catch {
            $consentFailures += 'Tenant.Read.All'
            Write-Warn "  Admin consent failed for 'Tenant.Read.All': $($_.Exception.Message)"
        }
    }

    # Assign Global Reader (read-only directory role) — clean lever for R-613 PowerShell surfaces.
    $globalReaderTemplateId = 'f2ef992c-3afb-46b9-b7cf-a126ee74c451'
    try {
        New-MgRoleManagementDirectoryRoleAssignment -BodyParameter @{
            PrincipalId      = $m365Sp.Id
            RoleDefinitionId = $globalReaderTemplateId
            DirectoryScopeId = '/'
        } -ErrorAction Stop | Out-Null
        Write-Host "    Assigned directory role: Global Reader" -ForegroundColor Gray
    } catch {
        Write-Warn "  Could not assign Global Reader (may already be assigned): $($_.Exception.Message)"
    }

    # R-613 Power Platform — register the M365 app as a Power Platform management application so it
    # can read tenant settings + DLP policies via the BAP admin REST API (SCUBA-PP-1.1/1.2/2.1/4.1 +
    # MT.1099/1100/1101). New-PowerAppManagementApp is .NET-Framework/PS-5.x-only (can't run in this
    # pwsh-7 script), so we call its REST equivalent. This endpoint REQUIRES a signed-in ADMIN USER
    # token (client-credentials is rejected) — the Connect-AzAccount session from Step 2 provides it;
    # the admin must hold Power Platform Administrator / Global Administrator (ManageAdminApplications).
    Write-Host "  Registering app as a Power Platform management application (BAP REST)..." -ForegroundColor Cyan
    try {
        $bapTokenObj = Get-AzAccessToken -ResourceUrl 'https://service.powerapps.com/' -ErrorAction Stop
        # Az.Accounts >= 5.0 returns the token as a SecureString by default; older versions return plaintext.
        $bapToken = if ($bapTokenObj.Token -is [System.Security.SecureString]) {
            [System.Net.NetworkCredential]::new('', $bapTokenObj.Token).Password
        } else { $bapTokenObj.Token }

        $ppRegUri = "https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/adminApplications/$($m365App.AppId)?api-version=2020-10-01"
        Invoke-RestMethod -Method Put -Uri $ppRegUri `
            -Headers @{ Authorization = "Bearer $bapToken" } -ContentType 'application/json' -ErrorAction Stop | Out-Null
        Write-Host "    Registered: Power Platform management application" -ForegroundColor Gray
    } catch {
        $consentFailures += 'Power Platform management app (New-PowerAppManagementApp)'
        Write-Warn "  Power Platform management-app registration failed: $($_.Exception.Message)"
        Write-Warn "  The signed-in admin must hold Power Platform Administrator / Global Administrator."
        Write-Warn "  Fallback (Windows PowerShell 5.1, as a PP admin): New-PowerAppManagementApp -ApplicationId $($m365App.AppId)"
    }

    # TODO (R-619): this OwnedBy + self-ownership logic overlaps Set-SelfManagedCertBootstrap; left inline because the M365 app also threads Exchange.ManageAsApp + Global Reader. Converge if that changes.
    # Self-ownership — Application.ReadWrite.OwnedBy only applies to apps the SP owns.
    try {
        $ownerRef = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($m365Sp.Id)" }
        New-MgApplicationOwnerByRef -ApplicationId $m365App.Id -BodyParameter $ownerRef -ErrorAction Stop
        Write-Host "    Set service principal as owner of its own app registration" -ForegroundColor Gray
    } catch {
        Write-Warn "  Could not set self-ownership (may already be owner): $($_.Exception.Message)"
    }

    # R-619 — make the Azure RM service principal (created via Az in Step 2) a self-managing
    # Graph app: grant Application.ReadWrite.OwnedBy + self-ownership so PAA can rotate its
    # own certificate. Done here because it needs the active Connect-MgGraph session.
    Write-Host "  Granting self-managed cert bootstrap to the Azure service principal..." -ForegroundColor Cyan
    Set-SelfManagedCertBootstrap `
        -AppId $azAppId `
        -Label 'Azure' `
        -GraphServicePrincipal $graphServicePrincipal `
        -ConsentFailures ([ref]$consentFailures)

    if ($consentFailures.Count -gt 0) {
        Write-Host ""
        Write-Host "  ACTION REQUIRED: The following permissions need manual admin consent in the Azure portal:" -ForegroundColor DarkYellow
        Write-Host "  Portal URL: https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/CallAnAPI/appId/$($m365App.AppId)/isMSAApp/" -ForegroundColor DarkYellow
        $consentFailures | ForEach-Object { Write-Host "    - $_" -ForegroundColor DarkYellow }
        Write-Host ""
    }

    $m365AppId = $m365App.AppId

    # Bootstrap-only secret: PAA discards it after generating the certificate (R-618).
    # Skipped in -PermissionsOnly (the app already has cert auth; no new credential needed).
    if (-not $PermissionsOnly) {
        $m365SecretExpiry = (Get-Date).AddDays(7)
        $m365SecretParams = @{
            ApplicationId      = $m365App.Id
            PasswordCredential = @{
                DisplayName = 'PAA-Secret'
                EndDateTime = $m365SecretExpiry
            }
        }
        $m365SecretResult = Add-MgApplicationPassword @m365SecretParams
        $m365SecretText = $m365SecretResult.SecretText
    }

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

if ($IncludeLogAnalytics -and -not $PermissionsOnly) {
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
        } elseif ($PermissionsOnly) {
            throw "PermissionsOnly: Defender CSPM SP '$defenderSpName' not found. Run without -PermissionsOnly to create it."
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

        $defenderAppId = $defenderSp.AppId

        # Bootstrap-only secret: PAA discards it after provisioning a self-rotating certificate (R-619).
        # 7-day expiry — NOT a long-lived credential. Skipped in -PermissionsOnly.
        if (-not $PermissionsOnly) {
            $defenderSecretExpiry = (Get-Date).AddDays(7)
            $defenderSecret = New-AzADAppCredential -ApplicationId $defenderSp.AppId -StartDate (Get-Date) -EndDate $defenderSecretExpiry
            $defenderSecretText = $defenderSecret.SecretText
        }

        # R-619 — same self-managed cert bootstrap as the Azure SP. The Connect-MgGraph
        # session from Step 3 is still active here.
        Write-Host "  Granting self-managed cert bootstrap to the Defender CSPM service principal..." -ForegroundColor Cyan
        Set-SelfManagedCertBootstrap `
            -AppId $defenderAppId `
            -Label 'Defender' `
            -GraphServicePrincipal $graphServicePrincipal `
            -ConsentFailures ([ref]$consentFailures)

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
# -PermissionsOnly: no secrets were generated, so there is no credentials file.
# Print a summary of what was (re)applied and exit before the credentials block.
# ---------------------------------------------------------------------------

if ($PermissionsOnly) {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "  PAA PERMISSIONS (RE)APPLIED — no secrets generated" -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "  Tenant ID         : $TenantId"
    Write-Host "  Azure SP          : $azSpName ($azAppId)"
    Write-Host "  M365 app          : $m365AppName ($m365AppId)"
    Write-Host "  Re-applied        : Azure roles (Reader/Security Reader/Cost Mgmt Reader);"
    Write-Host "                      Graph app roles + Exchange.ManageAsApp + Sites.FullControl.All"
    Write-Host "                      + Tenant.Read.All (Power BI) + Global Reader; Power Platform"
    Write-Host "                      management-app registration (BAP); self-managed cert ownership."
    if ($IncludeDefenderCspm -and $defenderAppId) {
        Write-Host "  Defender SP       : $defenderSpName ($defenderAppId) — Security Reader re-applied"
    }
    if ($consentFailures.Count -gt 0) {
        Write-Host ""
        Write-Host "  ACTION REQUIRED — grant these manually (admin consent in the Azure portal):" -ForegroundColor DarkYellow
        Write-Host "  https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/CallAnAPI/appId/$m365AppId/isMSAApp/" -ForegroundColor DarkYellow
        $consentFailures | ForEach-Object { Write-Host "    - $_" -ForegroundColor DarkYellow }
    }
    Write-Host ""
    Write-Host "  Power BI / Fabric (CIS §9): also enable 'Service principals can use read-only" -ForegroundColor Gray
    Write-Host "  Power BI admin APIs' in the Power BI admin portal (manual, one-time)." -ForegroundColor Gray
    Write-Host ""
    Write-Success "Permissions-only run complete. No credentials file written (existing cert auth unchanged)."
    return
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
$credLines += "# Azure SP roles: Reader, Security Reader, Cost Management Reader (on all listed subscriptions)"
$credLines += "# Azure SP Graph: Application.ReadWrite.OwnedBy (self-scoped) + owner of its own"
$credLines += "#                 app registration (R-619 self-rotating certificate)."
$credLines += "# M365 permissions (application/Role):"
$requiredGraphPermissions | ForEach-Object { $credLines += "#   - $_" }
$credLines += "#   - Exchange.ManageAsApp (Office 365 Exchange Online)"
$credLines += "#   - Sites.FullControl.All (SharePoint Online — R-613 PnP / Get-PnPTenant)"
$credLines += "#   - Tenant.Read.All (Power BI Service — CIS Section 9)"
$credLines += "#   - Directory role: Global Reader"
$credLines += "#   - Power Platform management app registration (BAP — R-613 SCUBA-PP / MT.109x)"
$credLines += "# MANUAL STEP STILL REQUIRED for Power BI / Microsoft Fabric checks (CIS Section 9):"
$credLines += "#   the 'Tenant.Read.All' app role above is granted, but a Power BI/Fabric Service Admin"
$credLines += "#   must ALSO enable 'Service principals can use read-only Power BI admin APIs' in the"
$credLines += "#   Power BI admin portal (Tenant settings). Without it the Admin API returns 401."
$credLines += "# POWER PLATFORM (R-613 SCUBA-PP / MT.109x): the script registers this app as a Power"
$credLines += "#   Platform management app via the BAP REST API, which requires the person RUNNING this"
$credLines += "#   script to be a Power Platform Administrator / Global Administrator. If that step warned"
$credLines += "#   above, register it manually in Windows PowerShell 5.1 as a PP admin:"
$credLines += "#     New-PowerAppManagementApp -ApplicationId $m365AppId"
$credLines += "#   Without it the BAP admin API returns 403 and PP checks stay ManualReview."
$credLines += "# NOTE: ALL client secrets below (Azure, M365$(if ($IncludeDefenderCspm) { ', Defender' })) are bootstrap-only"
$credLines += "#       (7-day expiry) and are discarded by PAA after it provisions a"
$credLines += "#       self-rotating certificate on each service principal."

if ($IncludeDefenderCspm) {
    $credLines += "# Defender SP roles: Security Reader (on all listed subscriptions)"
    $credLines += "# Defender SP Graph: Application.ReadWrite.OwnedBy (self-scoped) + owner of its"
    $credLines += "#                    own app registration (R-619 self-rotating certificate)."
}

$credLines += ""
$credLines += "# ============================================================"
$credLines += "#  NEXT STEPS"
$credLines += "# ============================================================"
$credLines += "# 1. Open PAA app and go to Settings > Integrations"
$credLines += "# 2. Enter Azure credentials (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)"
$credLines += "# 3. Enter M365 credentials (M365_CLIENT_ID, M365_CLIENT_SECRET, M365_TENANT_ID)"
$credLines += "#    (Power BI / Fabric checks) the 'Tenant.Read.All' app role is already granted;"
$credLines += "#    enable 'service principals can use read-only Power BI admin APIs' in the Power BI"
$credLines += "#    admin portal to activate CIS Section 9 — see PERMISSIONS GRANTED above."

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
Write-Host "  All secrets are bootstrap-only (7-day expiry) — PAA replaces each with a" -ForegroundColor DarkYellow
Write-Host "  self-rotating certificate and discards the secret (R-619)." -ForegroundColor DarkYellow
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
