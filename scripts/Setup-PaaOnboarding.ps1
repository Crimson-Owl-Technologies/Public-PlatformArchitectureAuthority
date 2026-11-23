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
    If set, prompts for a Log Analytics workspace ID. The workspace feeds BOTH the IAM Usage
    Visualizer (AzureActivity table) AND app-permission right-sizing
    (MicrosoftGraphActivityLogs table). The script automatically grants Log Analytics Reader
    on the workspace to the Azure service principal so PAA can query it even when the workspace
    lives in a subscription outside the scan scope. Use -EnableGraphActivityLogs to also turn
    on the Entra log stream that fills the MicrosoftGraphActivityLogs table.

.PARAMETER EnableGraphActivityLogs
    If set together with -IncludeLogAnalytics, creates an Entra ID diagnostic setting
    (PAA-GraphActivityLogs) that streams the MicrosoftGraphActivityLogs category to the
    Log Analytics workspace. Requires Entra ID P1 or P2 licence (the category is rejected
    without it); incurs Log Analytics ingestion cost (streams ALL tenant Graph API traffic);
    data is forward-only — no backfill, so allow 30-90 days before app-permission
    right-sizing data is meaningful. Has no effect without -IncludeLogAnalytics or if no
    workspace ID is entered.

.PARAMETER IncludeDefenderCspm
    If set, creates a separate Defender CSPM service principal with Security Reader on all
    subscriptions.

.PARAMETER AzureOnly
    If set, onboards Azure ONLY: no M365 Graph app registration is created, no Graph application
    permission is requested, no Exchange.ManageAsApp / Sites.FullControl.All / Power BI
    Tenant.Read.All app role is consented, the Global Reader directory role is not assigned, and
    the Power Platform management application is not registered. The Azure service principal still
    receives its three read-only Azure roles and the self-scoped Application.ReadWrite.OwnedBy
    grant it needs for certificate rotation.

    For customers whose security review permits Azure configuration reading but not Microsoft 365
    or directory access. M365, Entra ID and Zero Trust checks report as not evaluated. Mirrors the
    choice Setup-PaaLocalScan.ps1 offers via -IncludeM365 — note the polarity is inverted: local
    scan opts IN to M365, this script opts OUT, so that the existing default behaviour of hosted
    onboarding is unchanged.

.PARAMETER UseDeviceCode
    Sign in with a device code instead of an interactive browser window, for both the Azure and the
    Microsoft Graph connection.

    REQUIRED on a headless host — Linux, WSL or a container — where the default interactive flow has
    no browser to open. Without it on such a host, Connect-MgGraph returns WITHOUT raising an error
    and leaves no session, and the first Graph call then fails with "Authentication needed. Please
    call Connect-MgGraph."

.PARAMETER AzureCertificate
    Certificate mode. The public certificate PAA issued for the Azure principal, as base64
    DER. Supply it together with -M365Certificate; PAA builds the full command under "Set up
    automatically". In certificate mode the script creates no client secret and writes no
    credentials file: it attaches each certificate to its app registration, appending to the
    credentials the app already has, confirms it by reading the app back, and prints the four
    values PAA needs. It cannot be combined with -AzureOnly, -IncludeDefenderCspm, -IncludeLogAnalytics
    or -PermissionsOnly.

.PARAMETER M365Certificate
    Certificate mode. The public certificate PAA issued for the Microsoft 365 principal, as
    base64 DER. See -AzureCertificate.

.PARAMETER AzureClientId
    Certificate mode only. The application (client) ID of an existing PAA-Azure-<tenant prefix> app
    registration to reuse. The app must already be single-tenant, and it must hold no client secret,
    no certificate PAA did not issue, and no owner other than you and its own service principal;
    otherwise the run stops before writing anything. Without it, certificate mode
    creates a new app registration. When an app registration with that name already exists, it is
    left untouched and the new one gets the next free name (PAA-Azure-<tenant prefix>-2, -3, ...).
    A display name never selects the app to reuse: it is not unique, and anyone who can create an
    app can claim it.

.PARAMETER M365ClientId
    Certificate mode only. The application (client) ID of an existing PAA-M365 app registration to
    reuse. See -AzureClientId.

.PARAMETER KnownCertificateThumbprints
    Certificate mode only. The SHA-1 thumbprints of every certificate PAA has issued earlier for this
    connection, comma-separated, 40 hexadecimal characters each; PAA's command passes them. A reused
    app registration may hold only those certificates and the ones passed in this run: any other
    certificate, whatever its subject, means it is not reused.

.EXAMPLE
    .\Setup-PaaOnboarding.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

.EXAMPLE
    # On Linux, WSL or a container — sign in with a device code instead of a browser window:
    .\Setup-PaaOnboarding.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -UseDeviceCode

.EXAMPLE
    # Azure only — no Microsoft 365, Entra ID, SharePoint, Exchange or Power Platform access:
    .\Setup-PaaOnboarding.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -AzureOnly

.EXAMPLE
    .\Setup-PaaOnboarding.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -SubscriptionIds @("sub-id-1","sub-id-2") `
        -IncludeLogAnalytics `
        -IncludeDefenderCspm

.EXAMPLE
    # Re-apply permissions only (existing apps, no new secrets) — e.g. to grant newly-added
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
    [switch]$EnableGraphActivityLogs,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDefenderCspm,

    # Azure-only onboarding: skip the M365 Graph app registration entirely. See .PARAMETER AzureOnly.
    [Parameter(Mandatory = $false)]
    [switch]$AzureOnly,

    # Re-apply permissions/roles/registrations to EXISTING service principals only. Does NOT create
    # apps/SPs and does NOT generate any secret or credentials file. Use to grant newly-added
    # permissions (e.g. SharePoint Sites.FullControl.All, the Power Platform management-app
    # registration, Global Reader) to tenants onboarded before those were part of the script.
    [Parameter(Mandatory = $false)]
    [switch]$PermissionsOnly,

    # Sign in with a device code instead of an interactive browser window. REQUIRED on a
    # headless host — Linux, WSL or a container — where the default interactive flow has no browser
    # to open. Without it, Connect-MgGraph on such a host returns WITHOUT throwing and leaves no
    # session, and every later Graph call fails with "Authentication needed".
    [Parameter(Mandatory = $false)]
    [switch]$UseDeviceCode,

    # Certificate mode. Base64 DER public certificates PAA issued; see .PARAMETER AzureCertificate.
    [Parameter(Mandatory = $false)]
    [string]$AzureCertificate,

    [Parameter(Mandatory = $false)]
    [string]$M365Certificate,

    # Certificate mode only: reuse an app registration by its application (client) ID.
    [Parameter(Mandatory = $false)]
    [string]$AzureClientId,

    [Parameter(Mandatory = $false)]
    [string]$M365ClientId,

    # Certificate mode only: thumbprints of the certificates PAA issued earlier (see .PARAMETER).
    [Parameter(Mandatory = $false)]
    [string]$KnownCertificateThumbprints
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Certificate mode is on when either certificate parameter is passed; the validation below
# refuses a run that passes only one.
$certMode = $PSBoundParameters.ContainsKey('AzureCertificate') -or $PSBoundParameters.ContainsKey('M365Certificate')

# Bootstrap-secret lifetime (days). These client secrets are short-lived by design: PAA replaces each
# with a self-rotating certificate on first connect and discards the secret. The window
# only needs to outlast the gap between running this script and the operator entering the credentials in
# PAA. 30 days (was 7) gives comfortable slack so the credential doesn't die before the cert handoff,
# while still expiring on its own if migration never happens.
$bootstrapSecretDays = 30

# ---------------------------------------------------------------------------
# Grants
# ---------------------------------------------------------------------------
# every grant this script makes, by name, in one block, read by both modes. The test
# OnboardingScriptGrantManifestDriftTests compares this block with TenantConnectionGrantManifest
# (PAA's list of what an automated connection holds) and fails when they differ in the required,
# rotation or requested tiers; the Power Platform registration and self-ownership are not names
# here and are not compared. Names only:
# object and template ids are mapped or resolved outside the block. The operator's own sign-in
# scopes ($graphConnectScopes) are not grants either principal holds, so they are not here.
# Grants made only behind an opt-in switch (-IncludeLogAnalytics, -IncludeDefenderCspm) are not
# here either.

# BEGIN PAA-GRANTS
# Required Graph application permissions (type = Role) for the M365 app registration. Least-privilege
# set, cross-checked against actual collector/ZeroTrust endpoint usage. All read-only EXCEPT
# Application.ReadWrite.OwnedBy, which is self-scoped (manages only this app's own credential,
# for certificate bootstrap/rotation). Directory.Read.All is the umbrella for directory-object reads (applications,
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
    'Reports.Read.All',                      # assigned-but-inactive M365 license detection; degrades gracefully if absent
    'DeviceManagementManagedDevices.Read.All',
    'DeviceManagementConfiguration.Read.All',
    'DeviceManagementApps.Read.All',
    # Four collector endpoints have been failing with 403 on every tenant since they were
    # written, each naming the scope it wanted. Found by the Local Scan acceptance run (2026-08-13),
    # but the gap is here too — this list is where Local Scan's was ported from.
    # ⚠ Graph's 403 text also names "DeviceManagementServiceConfiguration.Read.All"; that is NOT a
    # real Graph app role. Only the shorter form below exists, and requesting the other silently
    # grants nothing.
    'DeviceManagementServiceConfig.Read.All',   # enrollment restrictions, MTD connectors, Autopilot
    'DeviceManagementRBAC.Read.All',            # Intune operation-approval policies
    'OnPremDirectorySynchronization.Read.All',  # Entra Connect sync configuration and state
    'SecurityEvents.Read.All',               # Defender alerts + secure score + DfO beta policies
    'SecurityIncident.Read.All',             # Defender incidents (CollectIncidentSummaryAsync)
    'SharePointTenantSettings.Read.All',     # SharePoint / OneDrive admin settings
    'NetworkAccess.Read.All',                # Global Secure Access / Entra Network config (config-only); degrades gracefully if absent / unlicensed
    'OrgSettings-Forms.Read.All',            # Microsoft Forms phishing-protection setting
    'DirectoryRecommendations.Read.All',     # Microsoft Entra recommendations
    'SecurityIdentitiesHealth.Read.All',     # Defender for Identity health issues
    'SecurityIdentitiesSensors.Read.All',    # Defender for Identity sensors
    'ThreatHunting.Read.All',                # Defender advanced hunting queries (exposure graph, Cloud Apps activity, device onboarding)
    'UserAuthenticationMethod.Read.All',     # authentication methods registered by privileged and break-glass accounts
    'AuthenticationContext.Read.All',        # Conditional Access authentication contexts
    'SensitivityLabels.Read.All',            # the tenant's sensitivity labels
    'AttackSimulation.Read.All',             # attack simulation training campaigns
    'IdentityRiskEvent.Read.All',            # risk detections on service principals
    'Application.ReadWrite.OwnedBy'          # self-scoped cert bootstrap/rotation (this app only)
)

# The self-scoped Graph app role the Azure (and Defender) principal needs to rotate its own
# certificate.
$rotationGraphPermission = 'Application.ReadWrite.OwnedBy'

# App roles on other first-party resources, for the M365 app registration (CIS Section 9).
$exchangeAppRole = 'Exchange.ManageAsApp'      # Office 365 Exchange Online
$sharePointAppRole = 'Sites.FullControl.All'   # SharePoint Online
$powerBiAppRole = 'Tenant.Read.All'            # Power BI Service

# The read-only directory role assigned to the M365 service principal.
$directoryRoleName = 'Global Reader'

# Azure roles assigned to the Azure service principal on every in-scope subscription.
$azureRoleNames = @('Reader', 'Security Reader', 'Cost Management Reader')
# END PAA-GRANTS

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

<#
.SYNOPSIS
    Whether the SIGNED-IN OPERATOR can create role assignments at a subscription scope.
.DESCRIPTION
    Ported from Setup-PaaLocalScan.ps1. Creating a role assignment needs Owner, User
    Access Administrator, or Role Based Access Control Administrator at the scope. The permissions API
    answers that read-only, in one call, BEFORE anything is created — so an onboarding run can say
    which subscriptions it will not be able to grant on instead of discovering it silently, one failed
    assignment at a time.

    Returns $true, $false, or $null when the probe itself could not run (treated as "attempt anyway").
#>
function Test-CanAssignRoles {
    param([string]$SubscriptionId)

    $uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/" +
           "Microsoft.Authorization/permissions?api-version=2022-04-01"

    try {
        $response = Invoke-AzRestMethod -Method GET -Uri $uri -ErrorAction Stop
        if ($response.StatusCode -ne 200) { return $null }

        foreach ($p in ($response.Content | ConvertFrom-Json).value) {
            foreach ($action in @($p.actions)) {
                if ($action -in @('*', 'Microsoft.Authorization/*',
                                  'Microsoft.Authorization/roleAssignments/*',
                                  'Microsoft.Authorization/roleAssignments/write')) {
                    $denied = @($p.notActions) | Where-Object {
                        $_ -in @('Microsoft.Authorization/roleAssignments/write',
                                 'Microsoft.Authorization/roleAssignments/*',
                                 'Microsoft.Authorization/*')
                    }
                    if (-not $denied) { return $true }
                }
            }
        }
        return $false
    } catch {
        return $null
    }
}

<#
.SYNOPSIS
    Assigns an Azure role and CONFIRMS it, returning what actually happened.
.DESCRIPTION
    ⚠ Every New-AzRoleAssignment in this script used to be `-ErrorAction SilentlyContinue` with
    no check of the result. On a subscription where the operator lacks
    Microsoft.Authorization/roleAssignments/write — which is an ordinary situation, not an
    exotic one — that printed "Assigning Reader on <sub>...", granted nothing, and went on to report
    "Azure service principal ready". Onboarding completed successfully, having produced a scanning
    identity that could not read the subscription.

    The failure is silent at provisioning time and only surfaces later, in a scan — and before
    before the scan-coverage fixes it would not have surfaced there either: an unreadable subscription returned zero
    resources and scored as a clean estate.

    The lesson was already in this file. The Log Analytics workspace grant verifies its own assignment,
    with the comment "Verify the assignment rather than assuming the silent call succeeded". It was
    learned once, in one place, and never applied to the main loop.

    ⚠ Deliberately never throws. Aborting onboarding for customers where it currently half-works would
    be a regression in behaviour even though it is an improvement in honesty — the caller reports the
    failures and continues.
.OUTPUTS
    A PSCustomObject: Subscription, Role, Outcome ('AlreadyAssigned'|'Granted'|'Failed'), Reason.
#>
function Grant-AzureRoleVerified {
    param(
        [string]$ObjectId,
        [string]$RoleDefinitionId,
        [string]$RoleName,
        [string]$Scope,
        [string]$SubscriptionName,
        [int]$VerifyRetries = 5,
        [int]$VerifyDelaySec = 3
    )

    $result = [pscustomobject]@{
        Subscription = $SubscriptionName
        Role         = $RoleName
        Outcome      = 'Failed'
        Reason       = $null
    }

    $existing = Get-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionId $RoleDefinitionId `
        -Scope $Scope -ErrorAction SilentlyContinue
    if ($existing) {
        $result.Outcome = 'AlreadyAssigned'
        return $result
    }

    try {
        New-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionId $RoleDefinitionId `
            -Scope $Scope -ErrorAction Stop | Out-Null
    } catch {
        # An already-existing assignment also throws; the read-back below settles which it was.
        $result.Reason = $_.Exception.Message.Split([char]10)[0]
    }

    # Verify, with a short poll. RBAC is eventually consistent — this file's own Log Analytics block
    # says "allow a few seconds for RBAC propagation". ⚠ The same lesson applies: a verification that
    # can produce a false negative must not drive anything destructive. Nothing here is destructive —
    # a failed confirmation is reported, never acted upon.
    for ($i = 0; $i -lt $VerifyRetries; $i++) {
        $confirmed = Get-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionId $RoleDefinitionId `
            -Scope $Scope -ErrorAction SilentlyContinue
        if ($confirmed) {
            $result.Outcome = 'Granted'
            $result.Reason = $null
            return $result
        }
        Start-Sleep -Seconds $VerifyDelaySec
    }

    if (-not $result.Reason) {
        $result.Reason = 'the call reported no error but the assignment is not readable afterwards'
    }
    return $result
}

# Turns an Az-created service principal into a self-managing Graph app:
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
        $ConsentFailures.Value += "$rotationGraphPermission ($Label)"
        return
    }
    $graphSp = Get-MgServicePrincipal -Filter "appId eq '$AppId'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $graphSp) {
        Write-Warn "  Could not resolve Graph service principal for $Label (appId $AppId) — skipping OwnedBy/self-ownership."
        $ConsentFailures.Value += "$rotationGraphPermission ($Label)"
        return
    }

    # Add Application.ReadWrite.OwnedBy to the app's requiredResourceAccess (Graph resource),
    # preserving any existing entries.
    $ownedByRole = $GraphServicePrincipal.AppRoles | Where-Object { $_.Value -eq $rotationGraphPermission }
    if (-not $ownedByRole) {
        Write-Warn "  '$rotationGraphPermission' app role not found on Microsoft Graph SP — skipping for $Label."
        $ConsentFailures.Value += "$rotationGraphPermission ($Label)"
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
        Write-Host "    [$Label] Added $rotationGraphPermission to requiredResourceAccess" -ForegroundColor Gray
    } catch {
        Write-Warn "  [$Label] Could not update requiredResourceAccess: $($_.Exception.Message)"
        $ConsentFailures.Value += "$rotationGraphPermission manifest ($Label)"
    }

    # Grant + admin-consent the app role to the SP.
    try {
        New-MgServicePrincipalAppRoleAssignment `
            -ServicePrincipalId $graphSp.Id `
            -PrincipalId $graphSp.Id `
            -ResourceId $GraphServicePrincipal.Id `
            -AppRoleId $ownedByRole.Id `
            -ErrorAction Stop | Out-Null
        Write-Host "    [$Label] Consented: $rotationGraphPermission" -ForegroundColor Gray
    } catch {
        if ($_.Exception.Message -match 'already exists') {
            Write-Warn "  [$Label] '$rotationGraphPermission' role already assigned (re-run); skipping."
        } else {
            $ConsentFailures.Value += "$rotationGraphPermission ($Label)"
            Write-Warn "  [$Label] Admin consent failed for '$rotationGraphPermission': $($_.Exception.Message)"
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

# Signs in to Microsoft Graph and verifies the session exists. Returns the context; exits the script
# when there is no session. Moved here unchanged from Step 3 so certificate mode can sign in before
# Step 2, where it creates the Azure app registration through Graph.
function Connect-PaaGraph {
    param (
        [Parameter(Mandatory = $true)][string]$TenantId,
        [Parameter(Mandatory = $true)][string[]]$Scopes,
        [switch]$UseDeviceCode
    )

    Write-Host "  Connecting to Microsoft Graph (tenant: $TenantId)..." -ForegroundColor Cyan

    # Connect-MgGraph can return WITHOUT THROWING and leave no session — observed on a headless
    # Linux host, where the default interactive flow has no browser to open. $ErrorActionPreference is
    # 'Stop' and it still did not stop, so the only reliable check is to ask for the context afterwards.
    $mgConnect = @{ TenantId = $TenantId; Scopes = $Scopes }
    if ($UseDeviceCode) { $mgConnect['UseDeviceCode'] = $true }
    try {
        Connect-MgGraph @mgConnect | Out-Null
    }
    catch {
        Write-Host "ERROR: Not signed in to Microsoft Graph - the connection did not complete, so the directory could not be read." -ForegroundColor Red
        Write-Host "       On a headless host (Linux, WSL or a container) re-run with -UseDeviceCode." -ForegroundColor Yellow
        Write-Host "       This is not a problem with your tenant." -ForegroundColor Yellow
        Write-Host "       Underlying error: $($_.Exception.Message)" -ForegroundColor DarkGray
        exit 1
    }

    # Verify the session EXISTS rather than trusting that the call returned. This is the check whose
    # absence turned an authentication failure into "the Microsoft Graph service principal is missing
    # from your tenant" — a claim that cannot be true of any tenant, and which sent the reader looking
    # for a directory defect instead of signing in.
    $context = Get-MgContext
    if (-not $context -or -not $context.Account) {
        Write-Host "ERROR: Not signed in to Microsoft Graph - the connection did not complete, so the directory could not be read." -ForegroundColor Red
        Write-Host "       On a headless host (Linux, WSL or a container) re-run with -UseDeviceCode." -ForegroundColor Yellow
        Write-Host "       This is not a problem with your tenant." -ForegroundColor Yellow
        exit 1
    }
    Write-Host "    Signed in as $($context.Account) (tenant $($context.TenantId))." -ForegroundColor Gray
    return $context
}

# ---------------------------------------------------------------------------
# Certificate mode helpers
# ---------------------------------------------------------------------------
# Certificate mode talks to Graph through Invoke-MgGraphRequest (Microsoft.Graph.Authentication)
# for keyCredentials, passwordCredentials and owners, so it depends on no cmdlet whose name changed
# between Graph PowerShell versions. Only public certificates pass through these functions; no
# secret is created, read or printed.

# Loads DER bytes as one public certificate, or returns $null. Only a plain certificate is parsed: a
# PKCS#12 blob is refused before anything loads it, so its private key is never imported, even by
# the fallback constructor on an older .NET. The caller disposes the result.
function Open-PaaCertificate {
    param ([byte[]]$Bytes)

    try {
        if ([System.Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($Bytes) -ne 'Cert') { return $null }
        $loader = 'System.Security.Cryptography.X509Certificates.X509CertificateLoader' -as [type]
        $cert = if ($loader) { $loader::LoadCertificate($Bytes) }
                else { [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Bytes) }
    } catch {
        return $null
    }
    if ($cert.HasPrivateKey) { $cert.Dispose(); return $null }
    return $cert
}

# Parses a -AzureCertificate / -M365Certificate value: base64 DER of one public certificate.
# Returns its DER bytes and SHA-1 thumbprint, or $null when the value is not a certificate
# or carries a private key (a PFX), which this script must never receive.
function ConvertFrom-PaaCertificateParameter {
    param ([string]$Base64Der)

    if ([string]::IsNullOrWhiteSpace($Base64Der)) { return $null }
    try {
        $bytes = [Convert]::FromBase64String($Base64Der.Trim())
    } catch {
        return $null
    }

    $cert = Open-PaaCertificate $bytes
    if (-not $cert) { return $null }
    try {
        return [pscustomobject]@{ Bytes = $cert.RawData; Thumbprint = $cert.Thumbprint.ToUpperInvariant() }
    } finally {
        $cert.Dispose()
    }
}

# Upper-case hex SHA-1 of a byte array: a certificate's thumbprint when given its DER bytes.
function Get-PaaSha1Hex {
    param ([byte[]]$Bytes)
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try { return [BitConverter]::ToString($sha1.ComputeHash($Bytes)).Replace('-', '') }
    finally { $sha1.Dispose() }
}

# The thumbprint of one keyCredential as Graph returns it: SHA-1 of its key (the certificate's DER)
# when the key was returned, else its customKeyIdentifier, which Graph defaults to the thumbprint.
function Get-PaaKeyCredentialThumbprint {
    param ($Credential)

    foreach ($field in 'key', 'customKeyIdentifier') {
        $value = $Credential[$field]
        if (-not $value) { continue }
        $bytes = if ($value -is [byte[]]) { $value } else { [Convert]::FromBase64String([string]$value) }
        if ($field -eq 'key') { return Get-PaaSha1Hex $bytes }
        return [BitConverter]::ToString($bytes).Replace('-', '')
    }
    return $null
}

# A Graph value as JSON can carry it back: dates as ISO 8601 UTC, bytes as base64. Graph sends dates
# as UTC ('...Z'): a parsed value of kind Unspecified is that UTC instant, one of kind Local was
# converted to local time and is converted back.
function ConvertTo-PaaGraphValue {
    param ($Value)
    if ($Value -is [datetime]) {
        $utc = switch ($Value.Kind) {
            'Utc'   { $Value }
            'Local' { $Value.ToUniversalTime() }
            default { [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
        }
        return $utc.ToString('o')
    }
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime.ToString('o') }
    if ($Value -is [byte[]]) { return [Convert]::ToBase64String($Value) }
    return $Value
}

# Reads the app's keyCredentials (a single-object GET with $select, the only read that returns each
# credential's key) and reports whether one has the given thumbprint and every credential in
# -RequiredKeyIds is still there. Retries briefly, because a read straight after a write can lag it.
function Test-PaaCertificateOnApp {
    param (
        [Parameter(Mandatory = $true)][string]$ApplicationObjectId,
        [Parameter(Mandatory = $true)][string]$Thumbprint,
        [string[]]$RequiredKeyIds = @(),
        [int]$Retries = 3,
        [int]$DelaySec = 3
    )

    for ($i = 0; $i -lt $Retries; $i++) {
        try {
            $app = Invoke-MgGraphRequest -Method GET -OutputType HashTable -ErrorAction Stop `
                -Uri ("v1.0/applications/$ApplicationObjectId" + '?$select=id,keyCredentials')
            $keys = @(@($app['keyCredentials']) | Where-Object { $_ })
            $found = @($keys | Where-Object { (Get-PaaKeyCredentialThumbprint $_) -eq $Thumbprint }).Count -gt 0
            $keyIds = @($keys | ForEach-Object { [string]$_['keyId'] })
            $kept = @($RequiredKeyIds | Where-Object { $_ -notin $keyIds }).Count -eq 0
            if ($found -and $kept) { return $true }
        } catch {
            Write-Host "    Could not read the app registration's certificates yet: $($_.Exception.Message)" -ForegroundColor Gray
        }
        if ($i -lt $Retries - 1) { Start-Sleep -Seconds $DelaySec }
    }
    return $false
}

# Attaches a certificate to an app registration by writing its keyCredentials back with the new one
# appended. Learn: addKey cannot be used on an app with no valid certificate, and updating
# keyCredentials replaces the collection, so every existing credential is written back unchanged.
# Writes nothing when an existing credential's key could not be read (writing it back without its
# key would remove it). Sets no customKeyIdentifier, so Graph defaults it to the thumbprint.
# Returns $true only when the read-back finds the thumbprint AND every credential that was there
# before the write, so a credential lost to a concurrent change is not reported as success.
function Add-PaaCertificateToApp {
    param (
        [Parameter(Mandatory = $true)][string]$ApplicationObjectId,
        [Parameter(Mandatory = $true)][byte[]]$CertificateBytes,
        [Parameter(Mandatory = $true)][string]$Thumbprint
    )

    try {
        $app = Invoke-MgGraphRequest -Method GET -OutputType HashTable -ErrorAction Stop `
            -Uri ("v1.0/applications/$ApplicationObjectId" + '?$select=id,keyCredentials')
    } catch {
        Write-Warn "  Could not read the app registration's certificates: $($_.Exception.Message)"
        return $false
    }

    $existing = @(@($app['keyCredentials']) | Where-Object { $_ })
    $existingKeyIds = @($existing | ForEach-Object { [string]$_['keyId'] } | Where-Object { $_ })
    if (@($existing | Where-Object { (Get-PaaKeyCredentialThumbprint $_) -eq $Thumbprint }).Count -gt 0) {
        Write-Host "    The certificate is already on the app registration." -ForegroundColor Gray
        return (Test-PaaCertificateOnApp -ApplicationObjectId $ApplicationObjectId -Thumbprint $Thumbprint -RequiredKeyIds $existingKeyIds)
    }
    if (@($existing | Where-Object { -not $_['key'] }).Count -gt 0) {
        Write-Warn "  An existing certificate on the app registration could not be read back in full, so none was added."
        return $false
    }

    $credentials = [System.Collections.Generic.List[object]]::new()
    foreach ($kc in $existing) {
        $entry = [ordered]@{}
        foreach ($field in 'keyId', 'type', 'usage', 'key', 'displayName', 'customKeyIdentifier', 'startDateTime', 'endDateTime') {
            if ($null -ne $kc[$field]) { $entry[$field] = ConvertTo-PaaGraphValue $kc[$field] }
        }
        $credentials.Add($entry)
    }
    $credentials.Add([ordered]@{
        type  = 'AsymmetricX509Cert'
        usage = 'Verify'
        key   = [Convert]::ToBase64String($CertificateBytes)
    })

    try {
        $body = @{ keyCredentials = $credentials.ToArray() } | ConvertTo-Json -Depth 5
        Invoke-MgGraphRequest -Method PATCH -Uri "v1.0/applications/$ApplicationObjectId" `
            -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null
        Write-Host "    Added the PAA certificate ($($existing.Count) existing credential(s) kept)" -ForegroundColor Gray
    } catch {
        Write-Warn "  Could not add the certificate to the app registration: $($_.Exception.Message)"
    }

    return (Test-PaaCertificateOnApp -ApplicationObjectId $ApplicationObjectId -Thumbprint $Thumbprint -RequiredKeyIds $existingKeyIds)
}

# The keyIds of an app's password credentials, or $null when they could not be read. Taken right
# after the app is resolved, before this run writes to it.
function Get-PaaPasswordKeyIds {
    param ([Parameter(Mandatory = $true)][string]$ApplicationObjectId)
    try {
        $app = Invoke-MgGraphRequest -Method GET -OutputType HashTable -ErrorAction Stop `
            -Uri ("v1.0/applications/$ApplicationObjectId" + '?$select=id,passwordCredentials')
        return ,[string[]]@(@($app['passwordCredentials']) | Where-Object { $_ } | ForEach-Object { [string]$_['keyId'] })
    } catch {
        return $null
    }
}

# Certificate mode creates no password credential, and removes none. This reports $true when the
# app holds no password credential whose keyId was absent when the run resolved it (-KnownKeyIds).
# It compares keyIds, not dates, and reports $false when either read failed, so a password that
# appeared during the run fails the target instead of being deleted or passed over.
function Test-PaaNoPasswordAddedThisRun {
    param (
        [Parameter(Mandatory = $true)][string]$ApplicationObjectId,
        [Parameter(Mandatory = $true)][string]$Label,
        [AllowNull()][AllowEmptyCollection()][string[]]$KnownKeyIds
    )

    $now = Get-PaaPasswordKeyIds -ApplicationObjectId $ApplicationObjectId
    if ($null -eq $KnownKeyIds -or $null -eq $now) {
        Write-Warn "  [$Label] Could not read the app registration's password credentials."
        return $false
    }
    $added = @($now | Where-Object { $_ -and $_ -notin $KnownKeyIds })
    if ($added.Count -gt 0) {
        Write-Warn "  [$Label] $($added.Count) password credential(s) appeared on the app registration during this run."
        return $false
    }
    return $true
}

# Leaves the app's own service principal as its only owner: removes every other owner, but only once
# the service principal is confirmed among the owners, so the app is never left without one.
# Returns $true only when the service principal is an owner and every other owner was removed.
function Set-PaaServicePrincipalAsOnlyOwner {
    param (
        [Parameter(Mandatory = $true)][string]$ApplicationObjectId,
        [Parameter(Mandatory = $true)][string]$ServicePrincipalId,
        [Parameter(Mandatory = $true)][string]$Label
    )

    try {
        $owners = @(Get-PaaGraphCollection -Uri ("v1.0/applications/$ApplicationObjectId/owners" + '?$select=id,displayName'))
    } catch {
        Write-Warn "  [$Label] Could not read the app registration's owners: $($_.Exception.Message)"
        return $false
    }

    if (-not ($owners | Where-Object { $_['id'] -eq $ServicePrincipalId })) {
        Write-Warn "  [$Label] The service principal is not an owner of its app registration, so no other owner was removed."
        return $false
    }

    $allRemoved = $true

    foreach ($owner in @($owners | Where-Object { $_['id'] -ne $ServicePrincipalId })) {
        try {
            Invoke-MgGraphRequest -Method DELETE -ErrorAction Stop `
                -Uri ("v1.0/applications/$ApplicationObjectId/owners/$($owner['id'])/" + '$ref') | Out-Null
            Write-Host "    [$Label] Removed owner $($owner['displayName']) ($($owner['id'])); the service principal is the only owner" -ForegroundColor Gray
        } catch {
            Write-Warn "  [$Label] Could not remove owner $($owner['displayName']) ($($owner['id'])): $($_.Exception.Message)"
            $allRemoved = $false
        }
    }
    return $allRemoved
}

# Certificate mode, after an app registration's grants and self-ownership: the PAA certificate
# attached and read back, and no password credential added during this run. Owners are left alone
# here: they are removed for both apps only once both are confirmed, just before C3, so every earlier
# rollback runs while the signed-in admin still owns what it deletes. A failure during owner removal
# stops it before the next target; an app whose own owner step had already taken the admin off it
# may then not delete, and Stop/C2 name it as "could not be removed". Returns $true only when both hold, so a
# failed check fails the target (copy C2) instead of ending in "Certificate mode complete".
function Complete-PaaCertModeApp {
    param (
        [Parameter(Mandatory = $true)][string]$ApplicationObjectId,
        [Parameter(Mandatory = $true)][string]$ServicePrincipalId,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][byte[]]$CertificateBytes,
        [Parameter(Mandatory = $true)][string]$Thumbprint,
        [AllowNull()][AllowEmptyCollection()][string[]]$KnownPasswordKeyIds
    )

    Write-Host "  [$Label] Attaching the PAA certificate..." -ForegroundColor Cyan
    $confirmed = Add-PaaCertificateToApp -ApplicationObjectId $ApplicationObjectId `
        -CertificateBytes $CertificateBytes -Thumbprint $Thumbprint
    if (-not $confirmed) { return $false }

    return (Test-PaaNoPasswordAddedThisRun -ApplicationObjectId $ApplicationObjectId -Label $Label `
        -KnownKeyIds $KnownPasswordKeyIds)
}

# Whether a failed app-role assignment failed because the principal already holds that role.
function Test-PaaAlreadyAssigned {
    param ($ErrorRecord)
    return ([string]$ErrorRecord.Exception.Message -match 'already exists')
}

# Every item of a Graph collection, following @odata.nextLink. A nextLink that leads anywhere but
# Graph itself throws: the collection is never silently cut short.
function Get-PaaGraphCollection {
    param (
        [Parameter(Mandatory = $true)][string]$Uri,
        # Sends ConsistencyLevel: eventual, which the transitive directory-role read requires.
        [switch]$Eventual
    )

    $headers = if ($Eventual) { @{ ConsistencyLevel = 'eventual' } } else { @{} }
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -Headers $headers -OutputType HashTable -ErrorAction Stop
        foreach ($item in @($page['value'])) { if ($item) { $items.Add($item) } }
        $link = [string]$page['@odata.nextLink']
        if ($link -and -not $link.StartsWith('https://graph.microsoft.com/', [StringComparison]::OrdinalIgnoreCase)) {
            throw "A Graph page pointed its next page outside graph.microsoft.com, so the list could not be read in full."
        }
        $next = if ($link) { $link } else { $null }
    }
    return $items.ToArray()
}

# The signed-in admin's directory object id, or $null when it cannot be read.
function Get-PaaSignedInObjectId {
    try {
        $me = Invoke-MgGraphRequest -Method GET -Uri ('v1.0/me' + '?$select=id') -OutputType HashTable -ErrorAction Stop
        return [string]$me['id']
    } catch {
        return $null
    }
}

# Whether a keyCredential is a certificate PAA issued: an AsymmetricX509Cert used
# to Verify whose thumbprint, the SHA-1 over its DER key bytes, is one of -Thumbprints: the
# certificates passed in this run and the ones PAA's command lists in -KnownCertificateThumbprints.
# A subject or issuer name proves nothing, since anyone who can write to the app can choose one, so
# neither is read. A credential whose key was not returned cannot be checked and does not count.
function Test-PaaIssuedKey {
    param ($Credential, [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Thumbprints)

    if ([string]$Credential['type'] -ne 'AsymmetricX509Cert' -or [string]$Credential['usage'] -ne 'Verify') { return $false }
    $value = $Credential['key']
    if (-not $value) { return $false }
    try {
        $bytes = if ($value -is [byte[]]) { $value } else { [Convert]::FromBase64String([string]$value) }
    } catch {
        return $false
    }
    return ((Get-PaaSha1Hex $bytes) -in @($Thumbprints | ForEach-Object { $_.ToUpperInvariant() }))
}

# Certificate mode, read-only, before any write: why an app registration may not be reused, or
# $null when it may. Rule: refuse an app holding any password credential,
# any key credential PAA did not issue, or any owner other than the signed-in admin and the app's
# own service principal. The same reading is applied to everything PAA's register step locks down
# so the script never reuses an app that register would refuse: federated
# credentials, the service principal's own credentials, owners and owned objects (none but its own
# application), app roles outside the grant list
# on any resource, directory roles outside it (direct, through a group, PIM eligible or active),
# and, for the Azure app, any Azure role other than the listed ones at subscription scope.
# Nothing is removed from the app.
function Get-PaaReuseRefusal {
    param (
        [Parameter(Mandatory = $true)]$App,
        # Thumbprints of the certificates PAA issued: this run's and -KnownCertificateThumbprints.
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$PaaThumbprints,
        [string]$SignedInObjectId,
        # Resource appId to the app-role values the grant list allows on it, for this target.
        [Parameter(Mandatory = $true)][hashtable]$AllowedAppRoles,
        # Directory role template ids allowed for this target (none for the Azure app).
        [AllowEmptyCollection()][string[]]$AllowedDirectoryRoleIds = @(),
        # The in-scope subscriptions and the Azure role names allowed on each; empty for the M365 app.
        [object[]]$Subscriptions = @(),
        # Role definition ids (GUIDs) of the Azure roles in the grant list.
        [AllowEmptyCollection()][string[]]$AllowedAzureRoleIds = @()
    )

    $read = Invoke-MgGraphRequest -Method GET -OutputType HashTable -ErrorAction Stop `
        -Uri ("v1.0/applications/$($App.Id)" + '?$select=id,passwordCredentials,keyCredentials')
    if (@(@($read['passwordCredentials']) | Where-Object { $_ }).Count -gt 0) {
        return 'a client secret'
    }
    if (@(@($read['keyCredentials']) | Where-Object { $_ -and -not (Test-PaaIssuedKey $_ $PaaThumbprints) }).Count -gt 0) {
        return 'a certificate PAA did not issue'
    }
    if (@(Get-PaaGraphCollection -Uri ("v1.0/applications/$($App.Id)/federatedIdentityCredentials" + '?$select=id')).Count -gt 0) {
        return 'a federated credential'
    }

    $sp = Get-MgServicePrincipal -Filter "appId eq '$($App.AppId)'" -ErrorAction Stop | Select-Object -First 1
    $allowedOwners = @($SignedInObjectId, $(if ($sp) { $sp.Id })) | Where-Object { $_ }
    $owners = @(Get-PaaGraphCollection -Uri ("v1.0/applications/$($App.Id)/owners" + '?$select=id'))
    if (@($owners | Where-Object { [string]$_['id'] -notin $allowedOwners }).Count -gt 0) {
        return 'an owner other than you and its own service principal'
    }
    if (-not $sp) { return $null }

    $spRead = Invoke-MgGraphRequest -Method GET -OutputType HashTable -ErrorAction Stop `
        -Uri ("v1.0/servicePrincipals/$($sp.Id)" + '?$select=id,passwordCredentials,keyCredentials')
    if (@(@($spRead['passwordCredentials']) | Where-Object { $_ }).Count -gt 0) {
        return 'a client secret'
    }
    if (@(@($spRead['keyCredentials']) | Where-Object { $_ -and -not (Test-PaaIssuedKey $_ $PaaThumbprints) }).Count -gt 0) {
        return 'a certificate PAA did not issue'
    }
    $spOwners = @(Get-PaaGraphCollection -Uri ("v1.0/servicePrincipals/$($sp.Id)/owners" + '?$select=id'))
    if (@($spOwners | Where-Object { [string]$_['id'] -notin $allowedOwners }).Count -gt 0) {
        return 'an owner other than you and its own service principal'
    }
    # The service principal may own its own application and nothing else: with
    # Application.ReadWrite.OwnedBy it could manage any other object it owns. Every page is read, and a
    # nextLink outside Graph throws (Get-PaaGraphCollection), so the check fails closed.
    $owned = @(Get-PaaGraphCollection -Uri ("v1.0/servicePrincipals/$($sp.Id)/ownedObjects" + '?$select=id'))
    if (@($owned | Where-Object { [string]$_['id'] -ne [string]$App.Id }).Count -gt 0) {
        return 'an owned object other than its own app registration'
    }

    $resources = @{}
    foreach ($assignment in @(Get-PaaGraphCollection -Uri "v1.0/servicePrincipals/$($sp.Id)/appRoleAssignments")) {
        $resourceId = [string]$assignment['resourceId']
        if (-not $resources.ContainsKey($resourceId)) {
            $resources[$resourceId] = Invoke-MgGraphRequest -Method GET -OutputType HashTable -ErrorAction Stop `
                -Uri ("v1.0/servicePrincipals/$resourceId" + '?$select=appId,appRoles')
        }
        $resource = $resources[$resourceId]
        $value = @(@($resource['appRoles']) | Where-Object { $_ -and [string]$_['id'] -eq [string]$assignment['appRoleId'] } |
            ForEach-Object { [string]$_['value'] }) | Select-Object -First 1
        $allowedValues = @($AllowedAppRoles[[string]$resource['appId']])
        if (-not $value -or $value -notin $allowedValues) {
            return 'an app role PAA does not request'
        }
    }

    $filter = [Uri]::EscapeDataString("principalId eq '$($sp.Id)'")
    $roleIds = [System.Collections.Generic.List[string]]::new()
    foreach ($uri in @(
            "v1.0/roleManagement/directory/roleAssignments?`$filter=$filter",
            "v1.0/roleManagement/directory/roleEligibilitySchedules?`$filter=$filter",
            "v1.0/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=$filter")) {
        foreach ($item in @(Get-PaaGraphCollection -Uri $uri)) { $roleIds.Add([string]$item['roleDefinitionId']) }
    }
    foreach ($item in @(Get-PaaGraphCollection -Uri "beta/roleManagement/directory/transitiveRoleAssignments?`$count=true&`$filter=$filter" -Eventual)) {
        $roleIds.Add([string]$item['roleDefinitionId'])
    }
    if (@($roleIds | Where-Object { $_ -notin $AllowedDirectoryRoleIds }).Count -gt 0) {
        return 'a directory role PAA does not request'
    }

    foreach ($sub in @($Subscriptions)) {
        $scope = "/subscriptions/$($sub.Id)"
        foreach ($assignment in @(Get-PaaAzureRoleAssignmentsFor -SubscriptionId $sub.Id -PrincipalId $sp.Id)) {
            $roleId = ([string]$assignment.roleDefinitionId -split '/')[-1]
            if ([string]$assignment.scope -ne $scope -or $roleId -notin $AllowedAzureRoleIds) {
                return 'an Azure role PAA does not request, or one above or below subscription scope'
            }
        }
    }
    return $null
}

# Every Azure role assignment that applies to a principal on one subscription, read with ARM's
# assignedTo() filter: at the subscription, inherited from above it, below it, and held through a
# group. Each item is the assignment's properties (scope, roleDefinitionId). Follows nextLink back
# to ARM only; any other answer throws.
function Get-PaaAzureRoleAssignmentsFor {
    param (
        [Parameter(Mandatory = $true)][string]$SubscriptionId,
        [Parameter(Mandatory = $true)][string]$PrincipalId
    )

    $filter = [Uri]::EscapeDataString("assignedTo('$PrincipalId')")
    $uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=$filter"
    $items = [System.Collections.Generic.List[object]]::new()
    while ($uri) {
        $response = Invoke-AzRestMethod -Method GET -Uri $uri -ErrorAction Stop
        if ($response.StatusCode -ne 200) { throw "Reading the Azure role assignments on subscription $SubscriptionId returned HTTP $($response.StatusCode)." }
        $page = $response.Content | ConvertFrom-Json
        foreach ($a in @($page.value)) { if ($a) { $items.Add($a.properties) } }
        $next = if ($page.PSObject.Properties['nextLink']) { [string]$page.nextLink } else { $null }
        if ($next -and -not $next.StartsWith('https://management.azure.com/', [StringComparison]::OrdinalIgnoreCase)) {
            throw "An Azure page pointed its next page outside management.azure.com, so the list could not be read in full."
        }
        $uri = $next
    }
    return $items.ToArray()
}

# Leaves the service principal with no owner but itself: removes every other owner of the service
# principal object (PAA's register refuses one with any). Returns $true when none is left.
function Set-PaaServicePrincipalOwnedOnlyBySelf {
    param (
        [Parameter(Mandatory = $true)][string]$ServicePrincipalId,
        [Parameter(Mandatory = $true)][string]$Label
    )

    try {
        $owners = @(Get-PaaGraphCollection -Uri ("v1.0/servicePrincipals/$ServicePrincipalId/owners" + '?$select=id,displayName'))
    } catch {
        Write-Warn "  [$Label] Could not read the service principal's owners: $($_.Exception.Message)"
        return $false
    }

    $allRemoved = $true
    foreach ($owner in @($owners | Where-Object { [string]$_['id'] -ne $ServicePrincipalId })) {
        try {
            Invoke-MgGraphRequest -Method DELETE -ErrorAction Stop `
                -Uri ("v1.0/servicePrincipals/$ServicePrincipalId/owners/$($owner['id'])/" + '$ref') | Out-Null
            Write-Host "    [$Label] Removed owner $($owner['displayName']) ($($owner['id'])) from the service principal" -ForegroundColor Gray
        } catch {
            Write-Warn "  [$Label] Could not remove owner $($owner['displayName']) ($($owner['id'])) from the service principal: $($_.Exception.Message)"
            $allRemoved = $false
        }
    }
    return $allRemoved
}

# Certificate mode, read-only: the name for an app registration this run creates. -BaseName when no
# app registration has it; otherwise -BaseName-2, -BaseName-3 and so on, the first that no app
# registration has. Every name starting with -BaseName is read, page by page, before one is chosen.
# An app that already has the name (say one an older secret-mode run created) is
# left exactly as it is, and the run creates a fresh app beside it.
function Get-PaaFreshAppName {
    param ([Parameter(Mandatory = $true)][string]$BaseName)

    $uri = 'v1.0/applications?$filter=' + [Uri]::EscapeDataString("startswith(displayName,'$BaseName')") + '&$select=displayName'
    $taken = @(Get-PaaGraphCollection -Uri $uri | ForEach-Object { [string]$_['displayName'] })
    if ($BaseName -notin $taken) { return $BaseName }
    for ($i = 2; ; $i++) {
        $candidate = "$BaseName-$i"
        if ($candidate -notin $taken) { return $candidate }
    }
}

# Certificate mode, read-only: the existing app registration to reuse, or $null to create one.
# Reuse is only by application (client) ID, and only of an app that carries the script's name
# prefix, is already single-tenant and passes Get-PaaReuseRefusal. A display name never selects
# the app to reuse. Throws, before anything is written, when the run must stop.
function Get-PaaCertModeExistingApp {
    param (
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [Parameter(Mandatory = $true)][string]$NamePrefix,
        [Parameter(Mandatory = $true)][string]$ParameterName,
        # Thumbprints of the certificates PAA issued: this run's and -KnownCertificateThumbprints.
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$PaaThumbprints,
        [string]$ClientId,
        [string]$SignedInObjectId,
        [Parameter(Mandatory = $true)][hashtable]$AllowedAppRoles,
        [AllowEmptyCollection()][string[]]$AllowedDirectoryRoleIds = @(),
        [object[]]$Subscriptions = @(),
        [AllowEmptyCollection()][string[]]$AllowedAzureRoleIds = @()
    )

    # Without an ID a new app is created, under a free name (Get-PaaFreshAppName); an app that
    # already has the name is never reused or changed.
    if (-not $ClientId) { return $null }

    $app = Get-MgApplication -Filter "appId eq '$ClientId'" -ErrorAction Stop | Select-Object -First 1
    if (-not $app) { throw (New-PaaCertModeStop "No app registration with application (client) ID $ClientId was found in this tenant.") }
    if (-not ([string]$app.DisplayName).StartsWith($NamePrefix, [StringComparison]::Ordinal)) {
        throw (New-PaaCertModeStop "The app registration with application (client) ID $ClientId is named '$($app.DisplayName)', not $NamePrefix<tenant prefix>, so it was not changed. Check -$ParameterName.")
    }
    if ($app.SignInAudience -ne 'AzureADMyOrg') {
        throw (New-PaaCertModeStop "The app registration $($app.DisplayName) accepts sign-ins from outside this tenant ($($app.SignInAudience)), so it was not changed. Certificate mode reuses single-tenant app registrations only.")
    }
    $reason = Get-PaaReuseRefusal -App $app -PaaThumbprints $PaaThumbprints -SignedInObjectId $SignedInObjectId `
        -AllowedAppRoles $AllowedAppRoles -AllowedDirectoryRoleIds $AllowedDirectoryRoleIds `
        -Subscriptions $Subscriptions -AllowedAzureRoleIds $AllowedAzureRoleIds
    if ($reason) {
        throw (New-PaaCertModeStop "The app registration $($app.DisplayName) was not reused because it has $reason, and it was left untouched. Run the command without -AzureClientId and -M365ClientId to create new PAA app registrations.")
    }
    return $app
}

# Certificate mode: the app registration and service principal for one target, from the result of
# Get-PaaCertModeExistingApp: reused when one was found, otherwise created. Every app it creates is
# added to -Created at once, so a later certificate-mode failure removes it: Steps 2 and 3 run inside
# try blocks whose catch is Stop-PaaCertModeRun, and the C2 exit calls Undo-PaaCertModeCreatedApps.
# The removal succeeds while the signed-in admin still owns the app, which is why owners are only
# removed after both certificates are confirmed.
# Also records the app's password keyIds before any grant, for Test-PaaNoPasswordAddedThisRun.
function Resolve-PaaCertModeApp {
    param (
        [Parameter(Mandatory = $true)][string]$DisplayName,
        $ExistingApp,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Created
    )

    $record = $null
    if ($ExistingApp) {
        $app = $ExistingApp
        Write-Host "  Reusing app registration $($app.DisplayName) (AppId: $($app.AppId))" -ForegroundColor Gray
    } else {
        Write-Host "  Creating app registration '$DisplayName'..." -ForegroundColor Cyan
        $app = New-MgApplication -DisplayName $DisplayName -SignInAudience 'AzureADMyOrg' -ErrorAction Stop
        $record = @{ ApplicationObjectId = $app.Id; DisplayName = $app.DisplayName; ServicePrincipalId = $null }
        $Created.Add($record)
    }
    $passwordKeyIds = Get-PaaPasswordKeyIds -ApplicationObjectId $app.Id

    $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($sp) {
        Write-Host "  Reusing existing service principal for '$($app.DisplayName)'..." -ForegroundColor Gray
    } else {
        Write-Host "  Creating service principal for '$($app.DisplayName)'..." -ForegroundColor Cyan
        $sp = New-MgServicePrincipal -AppId $app.AppId -ErrorAction Stop
        Wait-SpPropagation -ObjectId $sp.Id
    }
    if ($record) { $record.ServicePrincipalId = $sp.Id }

    return [pscustomobject]@{
        Id                  = $sp.Id
        AppId               = $app.AppId
        ApplicationObjectId = $app.Id
        DisplayName         = $app.DisplayName
        PasswordKeyIds      = $passwordKeyIds
        Created             = [bool]$record
        App                 = $app
    }
}

# Certificate mode: an expected stop, whose message is approved copy and is printed after "ERROR: "
# as it is. Anything else that fails is reported by Stop-PaaCertModeRun with the approved failure
# line, and its own message only as the "Underlying error".
function New-PaaCertModeStop {
    param ([Parameter(Mandatory = $true)][string]$Message)
    return [System.Management.Automation.ErrorRecord]::new(
        [System.InvalidOperationException]::new($Message), 'PaaCertModeStop',
        [System.Management.Automation.ErrorCategory]::InvalidOperation, $null)
}

# Certificate mode: the one way a failed run ends. Removes every app registration this run created
# and exits 1; it never throws. The line it prints says what actually happened:
#  - an app this run created could not be removed: the "could not be removed: {names}" line;
#  - else a reused app was written to before the failure: the "{name} was partly updated" line;
#  - else an expected stop: that stop's own approved message;
#  - else the approved failure line.
# Every line but an expected stop is followed by the raw message, in DarkGray, as "Underlying error".
function Stop-PaaCertModeRun {
    param (
        [Parameter(Mandatory = $true)]$ErrorRecord,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Created,
        [object[]]$Subscriptions = @(),
        # Display names of reused app registrations this run had begun to write to.
        [AllowEmptyCollection()][System.Collections.Generic.HashSet[string]]$PartlyUpdated = $null
    )

    $undo = Undo-PaaCertModeCreatedApps -Created $Created -Subscriptions $Subscriptions
    $partly = @(if ($PartlyUpdated) { $PartlyUpdated })
    if (-not $undo.AllRemoved) {
        Write-Host "ERROR: Certificate setup stopped, but these app registrations this run created could not be removed: $($undo.NotRemoved -join ', '). Delete them in the Microsoft Entra admin center under App registrations." -ForegroundColor Red
    } elseif ($partly.Count -gt 0) {
        Write-Host "ERROR: Certificate setup stopped. The app registrations this run created were removed. $($partly -join ', ') was partly updated before the failure; run the same command again to finish setting it up." -ForegroundColor Red
    } elseif ([string]$ErrorRecord.FullyQualifiedErrorId -like 'PaaCertModeStop*') {
        Write-Host "ERROR: $($ErrorRecord.Exception.Message)" -ForegroundColor Red
        exit 1
    } else {
        Write-Host "ERROR: Certificate setup stopped and the app registrations this run created were removed. Nothing was changed on existing app registrations." -ForegroundColor Red
    }
    Write-Host "       Underlying error: $($ErrorRecord.Exception.Message)" -ForegroundColor DarkGray
    exit 1
}

# Certificate mode: removes every app registration this run created (never a reused one), so a
# re-run of the same command starts clean. Azure role assignments go first, on the in-scope
# subscriptions only, so none is left pointing at a deleted principal; deleting the app registration
# then removes its service principal and the grants made to it. Returns AllRemoved, and NotRemoved:
# the display names of the app registrations it could not delete.
function Undo-PaaCertModeCreatedApps {
    param (
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Created,
        [object[]]$Subscriptions = @()
    )

    $notRemoved = [System.Collections.Generic.List[string]]::new()
    foreach ($record in @($Created)) {
        if ($record.ServicePrincipalId) {
            foreach ($sub in @($Subscriptions)) {
                $scope = "/subscriptions/$($sub.Id)"
                foreach ($assignment in @(Get-AzRoleAssignment -ObjectId $record.ServicePrincipalId -Scope $scope -ErrorAction SilentlyContinue |
                        Where-Object { $_.Scope -eq $scope })) {
                    try { Remove-AzRoleAssignment -InputObject $assignment -ErrorAction Stop | Out-Null }
                    catch { Write-Warn "  Could not remove a role assignment on $scope for $($record.DisplayName): $($_.Exception.Message)" }
                }
            }
        }
        try {
            Remove-MgApplication -ApplicationId $record.ApplicationObjectId -ErrorAction Stop
            Write-Host "  Removed the app registration $($record.DisplayName) that this run created." -ForegroundColor Yellow
        } catch {
            Write-Warn "  Could not remove the app registration $($record.DisplayName) that this run created: $($_.Exception.Message)"
            $notRemoved.Add([string]$record.DisplayName)
        }
    }
    $Created.Clear()
    return [pscustomobject]@{ AllRemoved = ($notRemoved.Count -eq 0); NotRemoved = $notRemoved.ToArray() }
}

# ---------------------------------------------------------------------------
# Certificate mode: refusals and certificate parsing, before anything signs in or writes
# ---------------------------------------------------------------------------
# Copy C1 is approved verbatim.

$azureCert = $null
$m365Cert = $null
$azureCertConfirmed = $false
$m365CertConfirmed = $false

if ($certMode) {
    if (-not $PSBoundParameters.ContainsKey('AzureCertificate') -or -not $PSBoundParameters.ContainsKey('M365Certificate')) {
        Write-Host "-AzureCertificate and -M365Certificate must be supplied together." -ForegroundColor Red
        exit 1
    }
    if ($AzureOnly) {
        Write-Host "Certificate mode connects Azure and Microsoft 365 together; it can't be combined with -AzureOnly." -ForegroundColor Red
        exit 1
    }
    if ($IncludeDefenderCspm) {
        Write-Host "-IncludeDefenderCspm isn't available in certificate mode. Run it separately without the certificate parameters." -ForegroundColor Red
        exit 1
    }
    if ($PermissionsOnly) {
        Write-Host "-PermissionsOnly isn't available in certificate mode." -ForegroundColor Red
        exit 1
    }
    if ($IncludeLogAnalytics) {
        # Refused in certificate mode, like -AzureOnly. Secret mode is unchanged.
        Write-Host "-IncludeLogAnalytics isn't available in certificate mode." -ForegroundColor Red
        exit 1
    }

    foreach ($clientId in @($AzureClientId, $M365ClientId)) {
        if ($clientId -and -not [Guid]::TryParseExact($clientId, 'D', [ref]([Guid]::Empty))) {
            Write-Host "-AzureClientId and -M365ClientId must be application (client) IDs, in the form xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx." -ForegroundColor Red
            exit 1
        }
    }
    if ($AzureClientId -and $M365ClientId -and [string]::Equals($AzureClientId, $M365ClientId, [StringComparison]::OrdinalIgnoreCase)) {
        Write-Host "-AzureClientId and -M365ClientId must name two different app registrations." -ForegroundColor Red
        exit 1
    }
    $knownThumbprints = @()
    if ($PSBoundParameters.ContainsKey('KnownCertificateThumbprints')) {
        $knownThumbprints = @($KnownCertificateThumbprints -split ',' | ForEach-Object { $_.Trim() })
        if ($knownThumbprints.Count -eq 0 -or @($knownThumbprints | Where-Object { $_ -notmatch '\A[0-9A-Fa-f]{40}\z' }).Count -gt 0) {
            Write-Host "-KnownCertificateThumbprints must be a comma-separated list of certificate thumbprints, 40 hexadecimal characters each. Copy the command from PAA again." -ForegroundColor Red
            exit 1
        }
        $knownThumbprints = @($knownThumbprints | ForEach-Object { $_.ToUpperInvariant() })
    }

    $azureCert = ConvertFrom-PaaCertificateParameter $AzureCertificate
    $m365Cert = ConvertFrom-PaaCertificateParameter $M365Certificate
    if (-not $azureCert -or -not $m365Cert) {
        Write-Host "-AzureCertificate and -M365Certificate must each be a public certificate, base64-encoded. Copy the command from PAA again." -ForegroundColor Red
        exit 1
    }
} elseif ($AzureClientId -or $M365ClientId) {
    Write-Host "-AzureClientId and -M365ClientId are used only in certificate mode." -ForegroundColor Red
    exit 1
} elseif ($PSBoundParameters.ContainsKey('KnownCertificateThumbprints')) {
    Write-Host "-KnownCertificateThumbprints is used only in certificate mode." -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# Step 1 — Dependency check
# ---------------------------------------------------------------------------

Write-Step "[1/5] Checking dependencies..."

# Certificate mode checks for the Graph submodules its cmdlets come from, not the
# Microsoft.Graph meta-module: Azure Cloud Shell ships "a basic set of Microsoft Graph PowerShell
# modules" (Applications, Authentication, Identity.Governance among them) and not the meta-module,
# so checking for it would stop every Cloud Shell run here. The secret mode's check is unchanged.
$certModeModules = @('Az.Accounts', 'Az.Resources', 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Applications', 'Microsoft.Graph.Identity.Governance')
$requiredModules = if ($certMode) { $certModeModules } else { @('Az.Accounts', 'Az.Resources', 'Microsoft.Graph') }
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

# Microsoft Graph sign-in scopes for the operator. Consent the admin gives Microsoft Graph PowerShell
# for this run, not grants either principal holds, so they sit outside the PAA-GRANTS block.
# Scopes needed:
#  - Application.ReadWrite.All        : create the app registration + set self-ownership
#  - AppRoleAssignment.ReadWrite.All  : grant admin consent (create app-role assignments)
#  - RoleManagement.ReadWrite.Directory: assign the Global Reader directory role
# Without AppRoleAssignment.ReadWrite.All every permission grant returns 403
# Authorization_RequestDenied. Re-running triggers a one-time consent prompt for these scopes.
# Under -AzureOnly the Global Reader role is never assigned, so RoleManagement.ReadWrite.Directory
# is not requested — the operator's consent prompt is narrowed to match what the run actually does.
$graphConnectScopes = @('Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All')
if (-not $AzureOnly) { $graphConnectScopes += 'RoleManagement.ReadWrite.Directory' }

# ---------------------------------------------------------------------------
# Step 2 — Azure service principal
# ---------------------------------------------------------------------------

Write-Step "[2/5] Creating Azure service principal..."

Write-Host "  Connecting to Azure (tenant: $TenantId)..." -ForegroundColor Cyan
# Same unchecked pattern as the Graph connect below used to have: verify the context exists
# rather than trusting that the call returned. This one happened to succeed on the headless host that
# exposed the Graph failure, which makes it a latent version of the same defect, not a safe one.
$azConnect = @{ TenantId = $TenantId }
if ($UseDeviceCode) { $azConnect['UseDeviceAuthentication'] = $true }
try {
    Connect-AzAccount @azConnect | Out-Null
}
catch {
    Write-Host "ERROR: Not signed in to Azure - the connection did not complete." -ForegroundColor Red
    Write-Host "       On a headless host (Linux, WSL or a container) re-run with -UseDeviceCode." -ForegroundColor Yellow
    Write-Host "       This is not a problem with your tenant." -ForegroundColor Yellow
    Write-Host "       Underlying error: $($_.Exception.Message)" -ForegroundColor DarkGray
    exit 1
}
$azContext = Get-AzContext
if (-not $azContext -or -not $azContext.Account) {
    Write-Host "ERROR: Not signed in to Azure - the connection did not complete." -ForegroundColor Red
    Write-Host "       On a headless host (Linux, WSL or a container) re-run with -UseDeviceCode." -ForegroundColor Yellow
    Write-Host "       This is not a problem with your tenant." -ForegroundColor Yellow
    exit 1
}
Write-Host "    Signed in as $($azContext.Account) (tenant $($azContext.Tenant.Id))." -ForegroundColor Gray

# Discover subscriptions
if ($SubscriptionIds -and $SubscriptionIds.Count -gt 0) {
    Write-Host "  Using $($SubscriptionIds.Count) specified subscription(s)..." -ForegroundColor Cyan
    # @(...) forces array context so .Count is valid even for a single subscription (Set-StrictMode Latest)
    $subscriptions = @($SubscriptionIds | ForEach-Object {
        Get-AzSubscription -SubscriptionId $_ -TenantId $TenantId
    })
} else {
    Write-Host "  Discovering all enabled subscriptions in tenant..." -ForegroundColor Cyan
    # @(...) forces array context: a tenant with one enabled subscription returns a scalar (or $null
    # when none match), and $subscriptions.Count below would otherwise throw under Set-StrictMode Latest.
    $subscriptions = @(Get-AzSubscription -TenantId $TenantId |
        Where-Object { $_.State -eq 'Enabled' })
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

# Built-in role definition ids for the names in the PAA-GRANTS block. The ids stay outside
# the block, which holds names only; a name the block adds without an id here fails the drift test.
$azureRoleDefinitionIds = @{
    'Reader'                 = $readerRoleId
    'Security Reader'        = $securityReaderRoleId
    'Cost Management Reader' = $costManagementReaderRoleId
}

# The directory role's template id, likewise outside the PAA-GRANTS block, which holds the role's name only.
$directoryRoleTemplateIds = @{ 'Global Reader' = 'f2ef992c-3afb-46b9-b7cf-a126ee74c451' }

# What a reused app may already hold, by target: the app roles in the grant list on each
# first-party resource (by its well-known application id), and the directory role. Get-PaaReuseRefusal
# refuses anything else, so the script never reuses an app PAA's register step would refuse.
$m365AllowedAppRoles = @{
    '00000003-0000-0000-c000-000000000000' = $requiredGraphPermissions      # Microsoft Graph
    '00000002-0000-0ff1-ce00-000000000000' = @($exchangeAppRole)            # Office 365 Exchange Online
    '00000003-0000-0ff1-ce00-000000000000' = @($sharePointAppRole)          # SharePoint Online
    '00000009-0000-0000-c000-000000000000' = @($powerBiAppRole)             # Power BI Service
}
$azureAllowedAppRoles = @{ '00000003-0000-0000-c000-000000000000' = @($rotationGraphPermission) }

$azSp = $null
$azSpCreated = $false
# Every app registration certificate mode creates in this run, for Undo-PaaCertModeCreatedApps.
$certCreatedApps = [System.Collections.Generic.List[object]]::new()
# Display names of reused app registrations this run has begun to write to (role assignments,
# requiredResourceAccess, app-role grants, owner reference, certificate). Each is added just before the
# first such write is attempted, so a failure after it is reported as "partly updated".
$certPartlyUpdated = [System.Collections.Generic.HashSet[string]]::new()
$m365Resolved = $null
if ($certMode) {
    # Certificate mode creates its app registrations through Graph, which creates no password
    # credential (New-AzADServicePrincipal -DisplayName may), so it signs in to Graph here. It resolves
    # BOTH apps before any grant: first the read-only lookups and pre-flight checks of any app it
    # would reuse, then the creation of the rest. A failure removes what this run created.
    $mgContext = Connect-PaaGraph -TenantId $TenantId -Scopes $graphConnectScopes -UseDeviceCode:$UseDeviceCode
    $signedInObjectId = Get-PaaSignedInObjectId
    # The certificates a reused app may hold: the two passed in this run and the ones PAA issued earlier.
    $paaThumbprints = @(@($azureCert.Thumbprint, $m365Cert.Thumbprint) + @($knownThumbprints))
    $m365CertModeName = "PAA-M365-$($TenantId.Substring(0, 8))"
    try {
        $azExisting = Get-PaaCertModeExistingApp -DisplayName $azSpName -NamePrefix 'PAA-Azure-' `
            -ParameterName 'AzureClientId' -ClientId $AzureClientId `
            -PaaThumbprints $paaThumbprints -SignedInObjectId $signedInObjectId `
            -AllowedAppRoles $azureAllowedAppRoles -Subscriptions $subscriptions `
            -AllowedAzureRoleIds @($azureRoleNames | ForEach-Object { $azureRoleDefinitionIds[$_] })
        $m365Existing = Get-PaaCertModeExistingApp -DisplayName $m365CertModeName -NamePrefix 'PAA-M365-' `
            -ParameterName 'M365ClientId' -ClientId $M365ClientId `
            -PaaThumbprints $paaThumbprints -SignedInObjectId $signedInObjectId `
            -AllowedAppRoles $m365AllowedAppRoles -AllowedDirectoryRoleIds @($directoryRoleTemplateIds[$directoryRoleName])
        # A new app takes a free name; one that already has the base name is left untouched.
        $azNewName = $azSpName
        $m365NewName = $m365CertModeName
        if (-not $azExisting) { $azNewName = Get-PaaFreshAppName -BaseName $azSpName }
        if (-not $m365Existing) { $m365NewName = Get-PaaFreshAppName -BaseName $m365CertModeName }
        foreach ($pair in @(@($azSpName, $azNewName), @($m365CertModeName, $m365NewName))) {
            if ($pair[0] -ne $pair[1]) {
                Write-Host "  An app registration named $($pair[0]) already exists and is left untouched; creating '$($pair[1])' instead." -ForegroundColor Gray
            }
        }
        $azSp = Resolve-PaaCertModeApp -DisplayName $azNewName -ExistingApp $azExisting -Created $certCreatedApps
        $m365Resolved = Resolve-PaaCertModeApp -DisplayName $m365NewName -ExistingApp $m365Existing -Created $certCreatedApps
        $azSpName = $azSp.DisplayName
    } catch {
        Stop-PaaCertModeRun -ErrorRecord $_ -Created $certCreatedApps -Subscriptions $subscriptions -PartlyUpdated $certPartlyUpdated
    }
}
try {
    if (-not $certMode) {
        $azSp = Get-AzADServicePrincipal -DisplayName $azSpName -ErrorAction SilentlyContinue
    }
    if ($certMode) {
        # Resolved above, before any grant.
    } elseif ($azSp) {
        Write-Host "  Reusing existing SP: $azSpName" -ForegroundColor Gray
    } elseif ($PermissionsOnly) {
        throw "PermissionsOnly: Azure SP '$azSpName' not found. Run without -PermissionsOnly to create it."
    } else {
        Write-Host "  Creating service principal '$azSpName'..." -ForegroundColor Cyan
        $azSp = New-AzADServicePrincipal -DisplayName $azSpName
        $azSpCreated = $true
        Wait-SpPropagation -ObjectId $azSp.Id
    }

    if ($certMode -and -not $azSp.Created) { [void]$certPartlyUpdated.Add($azSp.DisplayName) }
    # preflight, then assign and CONFIRM. See Grant-AzureRoleVerified for why the previous
    # -ErrorAction SilentlyContinue with no result check produced onboardings that reported success
    # while granting nothing.
    $roleResults = @()
    $azRoles = @($azureRoleNames | ForEach-Object { @{ Id = $azureRoleDefinitionIds[$_]; Name = $_ } })

    foreach ($sub in $subscriptions) {
        $scope = "/subscriptions/$($sub.Id)"

        if ((Test-CanAssignRoles -SubscriptionId $sub.Id) -eq $false) {
            # Stated once per subscription rather than three times as three identical failures.
            Write-Warn "    $($sub.Name): you cannot create role assignments here — skipping its $($azRoles.Count) roles."
            foreach ($role in $azRoles) {
                $roleResults += [pscustomobject]@{
                    Subscription = $sub.Name; Role = $role.Name; Outcome = 'Failed'
                    Reason = 'the signed-in operator has no Microsoft.Authorization/roleAssignments/write at this scope'
                }
            }
            continue
        }

        foreach ($role in $azRoles) {
            Write-Host "    Assigning $($role.Name) on $($sub.Name)..." -ForegroundColor Gray
            $roleResults += Grant-AzureRoleVerified -ObjectId $azSp.Id -RoleDefinitionId $role.Id `
                -RoleName $role.Name -Scope $scope -SubscriptionName $sub.Name
        }
    }

    $failedRoles = @($roleResults | Where-Object { $_.Outcome -eq 'Failed' })
    $confirmed = @($roleResults | Where-Object { $_.Outcome -in @('Granted', 'AlreadyAssigned') })

    Write-Host "    $($confirmed.Count) of $($roleResults.Count) role assignment(s) confirmed." -ForegroundColor Gray

    if ($failedRoles.Count -gt 0) {
        Write-Host ""
        Write-Warn "  $($failedRoles.Count) role assignment(s) could NOT be confirmed:"
        foreach ($f in $failedRoles) {
            Write-Warn "    - $($f.Subscription): $($f.Role) — $($f.Reason)"
        }
        Write-Host ""
        Write-Host "  Onboarding continues, and this is not fatal — but PAA will not be able to read" -ForegroundColor DarkCyan
        Write-Host "  those subscriptions. Its scans will report them as blind spots rather than as" -ForegroundColor DarkCyan
        Write-Host "  clean, so the gap is visible in the product; it is not visible to the customer" -ForegroundColor DarkCyan
        Write-Host "  unless someone acts on it. Creating a role assignment needs Owner, User Access" -ForegroundColor DarkCyan
        Write-Host "  Administrator, or Role Based Access Control Administrator at the subscription." -ForegroundColor DarkCyan
        Write-Host ""
    }

    # Optional, read-only: enable the Zero Trust standing-access check (AZ-RBAC-009). It reads role
    # assignments at the Azure ROOT scope '/' (above all subscriptions and management groups) to detect
    # standing User Access Administrator / Owner granted via "elevate access". Reading '/' needs a role
    # assignment AT '/', which a Global Admin can only grant after temporarily elevating access — so the
    # script does NOT do it automatically. Skip it and the check simply reports "Manual review".
    # not offered in certificate mode, whose principal holds Azure roles at subscription
    # scope only; PAA's register step refuses one with an assignment at the root or a management group.
    if (-not $certMode) {
        Write-Host ""
        Write-Host "  Optional - Zero Trust 'no standing access to Azure' check (AZ-RBAC-009):" -ForegroundColor DarkCyan
        Write-Host "    Reads role assignments at the Azure ROOT scope '/' (elevate-access detection)." -ForegroundColor Gray
        Write-Host "    Read-only and optional - without it the check reports 'Manual review'; nothing else is affected." -ForegroundColor Gray
        Write-Host "    To enable a real verdict, a Global Administrator runs (once):" -ForegroundColor Gray
        Write-Host "      1. Entra admin center > Properties > 'Access management for Azure resources' = Yes (elevate)" -ForegroundColor Gray
        Write-Host "      2. New-AzRoleAssignment -ObjectId $($azSp.Id) -RoleDefinitionId $readerRoleId -Scope '/'" -ForegroundColor Gray
        Write-Host "      3. Set 'Access management for Azure resources' back to No (optional)" -ForegroundColor Gray
    }

    $azAppId = $azSp.AppId

    # Bootstrap-only secret: PAA discards it after provisioning a self-rotating certificate.
    # Short-lived ($bootstrapSecretDays-day) — NOT a long-lived credential. Skipped in -PermissionsOnly,
    # and never created in certificate mode.
    if (-not $PermissionsOnly -and -not $certMode) {
        $azSecretExpiry = (Get-Date).AddDays($bootstrapSecretDays)
        $azSecret = New-AzADAppCredential -ApplicationId $azSp.AppId -StartDate (Get-Date) -EndDate $azSecretExpiry
        $azSecretText = $azSecret.SecretText
    }

    Write-Success "  Azure service principal ready: $azSpName (AppId: $azAppId)"
} catch {
    if ($azSpCreated -and $azSp) {
        try { Remove-AzADServicePrincipal -ObjectId $azSp.Id -Force -ErrorAction SilentlyContinue } catch {}
    }
    if ($certMode) {
        Stop-PaaCertModeRun -ErrorRecord $_ -Created $certCreatedApps -Subscriptions $subscriptions -PartlyUpdated $certPartlyUpdated
    }
    throw "Azure SP creation failed: $_"
}

# ---------------------------------------------------------------------------
# Step 3 — Graph session, Azure SP certificate bootstrap, and (unless -AzureOnly)
#          the M365 Graph app registration
# ---------------------------------------------------------------------------

if ($AzureOnly) {
    Write-Step "[3/5] Azure-only: certificate bootstrap (no M365 app registration)..."
} else {
    Write-Step "[3/5] Creating M365 Graph app registration..."
}

# Signed in by Connect-PaaGraph (moved unchanged into a function). Certificate mode signed in
# during Step 2, before creating the Azure app registration through Graph.
if (-not $certMode) {
    $mgContext = Connect-PaaGraph -TenantId $TenantId -Scopes $graphConnectScopes -UseDeviceCode:$UseDeviceCode
}

# Step 3, from the principal lookups through the M365 block, is one script block, dot-sourced
# below so its variables stay in script scope. In certificate mode it runs inside try, whose catch is
# Stop-PaaCertModeRun, so a failure here also removes the apps Step 2 created. The secret mode runs it
# without a try, exactly as before: a try would change what -ErrorAction SilentlyContinue suppresses
# inside it. (The body is not re-indented.)
$step3 = {
Write-Host "  Resolving Microsoft Graph service principal and permission IDs..." -ForegroundColor Cyan

# I3 — Filter by well-known AppId (stable, not display name)
# reached ONLY with a verified session, so a null result here really does mean the object is
# absent from the directory — which is what the message below is allowed to say, and could not say
# honestly before the check above existed.
$graphServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" |
    Select-Object -First 1
if (-not $graphServicePrincipal) {
    Write-Host "ERROR: Signed in to tenant $($mgContext.TenantId), but the Microsoft Graph service principal was not found in it." -ForegroundColor Red
    Write-Host "       This is unusual - every tenant normally has it. Authentication is NOT the problem here." -ForegroundColor Yellow
    if ($certMode) { $null = Undo-PaaCertModeCreatedApps -Created $certCreatedApps -Subscriptions $subscriptions }
    exit 1
}

$graphSpId = $graphServicePrincipal.Id
$graphAppId = $graphServicePrincipal.AppId   # Well-known: 00000003-0000-0000-c000-000000000000

# Declared up front so the credentials/summary blocks can test them on the -AzureOnly path, where
# no M365 app exists. Set-StrictMode would otherwise fault on the first unassigned reference.
$m365AppName = $null
$m365AppId = $null
$m365SecretText = $null
$consentFailures = @()

# Make the Azure RM service principal (created via Az in Step 2) a self-managing Graph app:
# grant Application.ReadWrite.OwnedBy + self-ownership so PAA can rotate its own certificate. Needs
# the active Connect-MgGraph session, which is why it lives in Step 3 rather than Step 2. It runs on
# BOTH paths — an -AzureOnly principal would otherwise be left on the expiring bootstrap secret with
# nothing to rotate it (the bug that made Azure-only onboarding unusable before this switch existed).
Write-Host "  Granting self-managed cert bootstrap to the Azure service principal..." -ForegroundColor Cyan
Set-SelfManagedCertBootstrap `
    -AppId $azAppId `
    -Label 'Azure' `
    -GraphServicePrincipal $graphServicePrincipal `
    -ConsentFailures ([ref]$consentFailures)

if ($certMode) {
    $azureCertConfirmed = Complete-PaaCertModeApp -ApplicationObjectId $azSp.ApplicationObjectId `
        -ServicePrincipalId $azSp.Id -Label 'Azure' -CertificateBytes $azureCert.Bytes `
        -Thumbprint $azureCert.Thumbprint -KnownPasswordKeyIds $azSp.PasswordKeyIds
}

if ($AzureOnly) {
    Write-Host ""
    Write-Host "  -AzureOnly: skipping the M365 Graph app registration." -ForegroundColor DarkCyan
    Write-Host "    NOT created  : PAA-M365-* app registration and service principal" -ForegroundColor Gray
    Write-Host "    NOT requested: every Microsoft Graph application permission" -ForegroundColor Gray
    Write-Host "    NOT consented: Exchange.ManageAsApp, Sites.FullControl.All, Tenant.Read.All" -ForegroundColor Gray
    Write-Host "    NOT assigned : Global Reader directory role" -ForegroundColor Gray
    Write-Host "    NOT registered: Power Platform management application" -ForegroundColor Gray
    Write-Host "    Consequence  : M365, Entra ID and Zero Trust checks report as not evaluated." -ForegroundColor Gray
    Write-Host ""

    if ($consentFailures.Count -gt 0) {
        Write-Host "  ACTION REQUIRED: the following need manual admin consent in the Azure portal:" -ForegroundColor DarkYellow
        Write-Host "  https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/CallAnAPI/appId/$azAppId/isMSAApp/" -ForegroundColor DarkYellow
        $consentFailures | ForEach-Object { Write-Host "    - $_" -ForegroundColor DarkYellow }
        Write-Host ""
    }
}

# The M365 Graph app registration. Skipped entirely under -AzureOnly: no app, no Graph
# permission, no Exchange/SharePoint/Power BI app role, no Global Reader, no Power Platform
# registration. See .PARAMETER AzureOnly.
if (-not $AzureOnly) {
    # Stable app name based on tenant ID — idempotent across runs
    $m365AppName = "PAA-M365-$($TenantId.Substring(0, 8))"

    # $requiredGraphPermissions is defined in the PAA-GRANTS block at the top of the script.

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

    # Office 365 Exchange Online (for PowerShell collection) — Exchange.ManageAsApp app role.
    $exoAppId = '00000002-0000-0ff1-ce00-000000000000'
    $exoSp = Get-MgServicePrincipal -Filter "appId eq '$exoAppId'" | Select-Object -First 1
    $exoResourceAccess = @()
    if ($exoSp) {
        $exoRole = $exoSp.AppRoles | Where-Object { $_.Value -eq $exchangeAppRole }
        if ($exoRole) {
            $exoResourceAccess += @{ Id = $exoRole.Id; Type = 'Role' }
        } else {
            Write-Warn "  '$exchangeAppRole' app role not found on Exchange Online SP — skipping."
        }
    } else {
        Write-Warn "  Office 365 Exchange Online service principal not found in tenant — skipping $exchangeAppRole."
    }

    # SharePoint Online (for PnP collection — Get-PnPTenant / Get-PnPTenantSite) — Sites.FullControl.All app role.
    $spoAppId = '00000003-0000-0ff1-ce00-000000000000'
    $spoSp = Get-MgServicePrincipal -Filter "appId eq '$spoAppId'" | Select-Object -First 1
    $spoResourceAccess = @()
    if ($spoSp) {
        $spoRole = $spoSp.AppRoles | Where-Object { $_.Value -eq $sharePointAppRole }
        if ($spoRole) {
            $spoResourceAccess += @{ Id = $spoRole.Id; Type = 'Role' }
        } else {
            Write-Warn "  '$sharePointAppRole' app role not found on SharePoint Online SP — skipping."
        }
    } else {
        Write-Warn "  SharePoint Online service principal not found in tenant — skipping $sharePointAppRole."
    }

    # Power BI Service (for CIS Section 9 Power BI / Fabric checks) — Tenant.Read.All app role.
    # NOTE: this grant is necessary but NOT sufficient — a Power BI/Fabric Service Admin must ALSO enable
    # "Service principals can use read-only Power BI admin APIs" in the Power BI admin portal (Tenant settings).
    $pbiAppId = '00000009-0000-0000-c000-000000000000'
    $pbiSp = Get-MgServicePrincipal -Filter "appId eq '$pbiAppId'" | Select-Object -First 1
    $pbiResourceAccess = @()
    if ($pbiSp) {
        $pbiRole = $pbiSp.AppRoles | Where-Object { $_.Value -eq $powerBiAppRole }
        if ($pbiRole) {
            $pbiResourceAccess += @{ Id = $pbiRole.Id; Type = 'Role' }
        } else {
            Write-Warn "  '$powerBiAppRole' app role not found on Power BI Service SP — skipping."
        }
    } else {
        Write-Warn "  Power BI Service service principal not found in tenant — skipping $powerBiAppRole."
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
    $existingM365App = $null
    $m365PasswordKeyIds = $null
    try {
        if ($certMode) {
            # Resolved in Step 2, before any grant (reused by application ID, or created).
            $m365App = $m365Resolved.App
            $m365AppName = $m365Resolved.DisplayName
            $m365PasswordKeyIds = $m365Resolved.PasswordKeyIds
            if ($m365Resolved.Created) {
                try {
                    Update-MgApplication -ApplicationId $m365App.Id -RequiredResourceAccess $requiredResourceAccess -ErrorAction Stop
                    Write-Host "    Updated app manifest with current required permissions" -ForegroundColor Gray
                } catch {
                    Write-Warn "  Could not update app manifest (continuing — consents are granted directly): $($_.Exception.Message)"
                }
            }
        } else {
            $existingM365App = Get-MgApplication -Filter "displayName eq '$m365AppName'" -ErrorAction SilentlyContinue |
                Select-Object -First 1
        }
        if ($certMode) {
            # Handled above.
        } elseif ($existingM365App) {
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

        $existingM365Sp =Get-MgServicePrincipal -Filter "appId eq '$($m365App.AppId)'" -ErrorAction SilentlyContinue |
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
        if ($certMode -and -not $m365Resolved.Created) { [void]$certPartlyUpdated.Add($m365Resolved.DisplayName) }
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
                if (Test-PaaAlreadyAssigned $_) {
                    Write-Warn "  [M365] '$permName' role already assigned (re-run); skipping."
                } else {
                    $consentFailures += $permName
                    Write-Warn "  Admin consent failed for '$permName': $($_.Exception.Message)"
                }
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
                Write-Host "    Consented: $exchangeAppRole" -ForegroundColor Gray
            } catch {
                if (Test-PaaAlreadyAssigned $_) {
                    Write-Warn "  [M365] '$exchangeAppRole' role already assigned (re-run); skipping."
                } else {
                    $consentFailures += $exchangeAppRole
                    Write-Warn "  Admin consent failed for '$exchangeAppRole': $($_.Exception.Message)"
                }
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
                Write-Host "    Consented: $sharePointAppRole (SharePoint)" -ForegroundColor Gray
            } catch {
                if (Test-PaaAlreadyAssigned $_) {
                    Write-Warn "  [M365] '$sharePointAppRole' role already assigned (re-run); skipping."
                } else {
                    $consentFailures += $sharePointAppRole
                    Write-Warn "  Admin consent failed for '$sharePointAppRole': $($_.Exception.Message)"
                }
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
                Write-Host "    Consented: $powerBiAppRole (Power BI)" -ForegroundColor Gray
            } catch {
                if (Test-PaaAlreadyAssigned $_) {
                    Write-Warn "  [M365] '$powerBiAppRole' role already assigned (re-run); skipping."
                } else {
                    $consentFailures += $powerBiAppRole
                    Write-Warn "  Admin consent failed for '$powerBiAppRole': $($_.Exception.Message)"
                }
            }
        }

        # Assign Global Reader (read-only directory role) — clean lever for PowerShell surfaces.
        $globalReaderTemplateId = $directoryRoleTemplateIds[$directoryRoleName]
        try {
            New-MgRoleManagementDirectoryRoleAssignment -BodyParameter @{
                PrincipalId      = $m365Sp.Id
                RoleDefinitionId = $globalReaderTemplateId
                DirectoryScopeId = '/'
            } -ErrorAction Stop | Out-Null
            Write-Host "    Assigned directory role: $directoryRoleName" -ForegroundColor Gray
        } catch {
            Write-Warn "  Could not assign $directoryRoleName (may already be assigned): $($_.Exception.Message)"
        }

        # Power Platform — register the M365 app as a Power Platform management application so it
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

        # Note: this OwnedBy + self-ownership logic overlaps Set-SelfManagedCertBootstrap; left inline because the M365 app also threads Exchange.ManageAsApp + Global Reader. Converge if that changes.
        # Self-ownership — Application.ReadWrite.OwnedBy only applies to apps the SP owns.
        try {
            $ownerRef = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($m365Sp.Id)" }
            New-MgApplicationOwnerByRef -ApplicationId $m365App.Id -BodyParameter $ownerRef -ErrorAction Stop
            Write-Host "    Set service principal as owner of its own app registration" -ForegroundColor Gray
        } catch {
            Write-Warn "  Could not set self-ownership (may already be owner): $($_.Exception.Message)"
        }

        # (The Azure SP's own cert bootstrap now runs at the top of Step 3, before this block, so that
        # -AzureOnly still gets it.)

        if ($certMode) {
            $m365CertConfirmed = Complete-PaaCertModeApp -ApplicationObjectId $m365App.Id `
                -ServicePrincipalId $m365Sp.Id -Label 'M365' -CertificateBytes $m365Cert.Bytes `
                -Thumbprint $m365Cert.Thumbprint -KnownPasswordKeyIds $m365PasswordKeyIds
        }

        if ($consentFailures.Count -gt 0) {
            Write-Host ""
            Write-Host "  ACTION REQUIRED: The following permissions need manual admin consent in the Azure portal:" -ForegroundColor DarkYellow
            Write-Host "  Portal URL: https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/CallAnAPI/appId/$($m365App.AppId)/isMSAApp/" -ForegroundColor DarkYellow
            $consentFailures | ForEach-Object { Write-Host "    - $_" -ForegroundColor DarkYellow }
            Write-Host ""
        }

        $m365AppId = $m365App.AppId

        # Bootstrap-only secret: PAA discards it after generating the certificate.
        # Skipped in -PermissionsOnly (the app already has cert auth; no new credential needed), and
        # never created in certificate mode.
        if (-not $PermissionsOnly -and -not $certMode) {
            $m365SecretExpiry = (Get-Date).AddDays($bootstrapSecretDays)
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
        if ($certMode) {
            # the Step 3 catch below removes both app registrations this run created.
            throw
        }
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
}
}
if ($certMode) {
    try { . $step3 } catch { Stop-PaaCertModeRun -ErrorRecord $_ -Created $certCreatedApps -Subscriptions $subscriptions -PartlyUpdated $certPartlyUpdated }
} else {
    . $step3
}

# ---------------------------------------------------------------------------
# Step 4 — Optional Log Analytics
# ---------------------------------------------------------------------------

$logAnalyticsWorkspaceId = $null
$workspaceArmId          = $null   # resolved ARM resource ID of the workspace
$workspaceRoleGranted    = $false  # whether Log Analytics Reader was granted to $azSp
$graphDiagSettingEnabled = $false  # whether MicrosoftGraphActivityLogs diag setting was created

Write-Step "[4/5] Log Analytics configuration..."

if ($IncludeLogAnalytics -and -not $PermissionsOnly) {
    Write-Host "  The workspace feeds both the IAM Usage Visualizer (AzureActivity) and" -ForegroundColor Cyan
    Write-Host "  app-permission right-sizing (MicrosoftGraphActivityLogs). Use -EnableGraphActivityLogs" -ForegroundColor Cyan
    Write-Host "  to also turn on the Entra log stream for MicrosoftGraphActivityLogs." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Enter your Log Analytics Workspace ID (from Azure portal > Log Analytics workspace > Overview):" -ForegroundColor Cyan
    $logAnalyticsWorkspaceId = Read-Host "  Workspace ID"
    if ([string]::IsNullOrWhiteSpace($logAnalyticsWorkspaceId)) {
        Write-Warn "  No workspace ID provided — Log Analytics will be skipped in output."
        $logAnalyticsWorkspaceId = $null
    } elseif (-not [Guid]::TryParse($logAnalyticsWorkspaceId, [ref]([Guid]::Empty))) {
        Write-Warn "  Workspace ID must be the GUID from the Log Analytics workspace Overview blade (form xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx), not a resource path or name — skipping Log Analytics setup."
        $logAnalyticsWorkspaceId = $null
    } else {
        Write-Success "  Log Analytics workspace ID recorded."

        # ------------------------------------------------------------------
        # 4a. Resolve workspace GUID → ARM resource ID via Azure Resource Graph
        # ------------------------------------------------------------------
        Write-Host "  Resolving workspace ARM resource ID via Resource Graph..." -ForegroundColor Cyan
        try {
            $rgQueryBody = [ordered]@{
                query   = "resources | where type =~ 'microsoft.operationalinsights/workspaces' | where properties.customerId =~ '$logAnalyticsWorkspaceId' | project id, name, resourceGroup, subscriptionId"
                options = [ordered]@{ resultFormat = 'objectArray' }
            } | ConvertTo-Json -Depth 5

            $rgResponse = Invoke-AzRestMethod -Path '/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01' -Method POST -Payload $rgQueryBody
            if ($rgResponse.StatusCode -in 200, 201) {
                $rgResult = $rgResponse.Content | ConvertFrom-Json
                if ($rgResult.data -and @($rgResult.data).Count -gt 0) {
                    $workspaceArmId = @($rgResult.data)[0].id
                    Write-Host "  Workspace ARM ID : $workspaceArmId" -ForegroundColor Gray
                } else {
                    Write-Warn "  Could not resolve workspace '$logAnalyticsWorkspaceId' in Resource Graph — no matching workspace found. Check the ID and that you have Reader access to its subscription. Workspace role grant and diagnostic setting will be skipped."
                }
            } else {
                Write-Warn "  Resource Graph query returned HTTP $($rgResponse.StatusCode) — could not resolve workspace ARM ID; skipping workspace role grant and diagnostic setting. Response: $($rgResponse.Content)"
            }
        } catch {
            Write-Warn "  Resource Graph query failed: $($_.Exception.Message) — skipping workspace role grant and diagnostic setting."
        }

        # ------------------------------------------------------------------
        # 4b. Assign Log Analytics Reader on the workspace to the Azure SP
        # ------------------------------------------------------------------
        if ($workspaceArmId) {
            $laReaderRoleId = '73c42c96-874c-492b-b04d-ab87d138a893'  # Log Analytics Reader
            if ($azSp) {
                Write-Host "  Assigning Log Analytics Reader on workspace to $azSpName..." -ForegroundColor Cyan

                # this block already verified — it is where the lesson was first learned, and
                # its comment asked for exactly the retry the shared helper now provides ("allow a few
                # seconds for RBAC propagation and re-run"). Folded onto Grant-AzureRoleVerified so
                # there is one implementation rather than a good one here and none in the main loop.
                # The scope is a workspace rather than a subscription; the helper does not care.
                $workspaceResult = Grant-AzureRoleVerified -ObjectId $azSp.Id `
                    -RoleDefinitionId $laReaderRoleId -RoleName 'Log Analytics Reader' `
                    -Scope $workspaceArmId -SubscriptionName 'workspace'

                if ($workspaceResult.Outcome -in @('Granted', 'AlreadyAssigned')) {
                    $workspaceRoleGranted = $true
                    Write-Success "  Log Analytics Reader confirmed on workspace (allows PAA to query workspaces outside scan subscriptions)."
                } else {
                    Write-Warn "  Log Analytics Reader could not be confirmed — $($workspaceResult.Reason)"
                    Write-Warn "  A manual grant may be needed; PAA cannot query this workspace without it."
                }
            } else {
                Write-Warn "  Azure service principal not available — skipping Log Analytics Reader grant on workspace."
            }

            # ------------------------------------------------------------------
            # 4c. Optional: enable Entra MicrosoftGraphActivityLogs diagnostic setting
            # ------------------------------------------------------------------
            if ($EnableGraphActivityLogs) {
                Write-Host ""
                Write-Host "  +-[ MicrosoftGraphActivityLogs diagnostic setting ]----------------------------+" -ForegroundColor DarkYellow
                Write-Host "  | This creates an Entra ID tenant-level diagnostic setting that streams ALL   |" -ForegroundColor DarkYellow
                Write-Host "  | Graph API traffic (MicrosoftGraphActivityLogs) to your workspace.           |" -ForegroundColor DarkYellow
                Write-Host "  |                                                                              |" -ForegroundColor DarkYellow
                Write-Host "  | REQUIREMENTS:  Entra ID P1 or P2 licence (category rejected without it)    |" -ForegroundColor DarkYellow
                Write-Host "  | COST:          Log Analytics ingestion cost — all tenant Graph API traffic  |" -ForegroundColor DarkYellow
                Write-Host "  | FORWARD-ONLY:  No backfill. Allow 30-90 days before right-sizing           |" -ForegroundColor DarkYellow
                Write-Host "  |                data is meaningful.                                          |" -ForegroundColor DarkYellow
                Write-Host "  +------------------------------------------------------------------------------+" -ForegroundColor DarkYellow
                Write-Host ""
                $confirmDiag = Read-Host "  Enable Graph activity log stream? Type 'yes' to confirm (anything else skips)"
                if ($confirmDiag -eq 'yes') {
                    try {
                        $diagSettingName = 'PAA-GraphActivityLogs'
                        $diagPayload = [ordered]@{
                            properties = [ordered]@{
                                workspaceId = $workspaceArmId
                                logs        = @(
                                    [ordered]@{
                                        category = 'MicrosoftGraphActivityLogs'
                                        enabled  = $true
                                    }
                                )
                            }
                        } | ConvertTo-Json -Depth 5

                        # api-version 2017-04-01-preview is the widely-supported version for
                        # /providers/microsoft.aadiam/diagnosticSettings — there is no GA
                        # equivalent for this endpoint; the preview designation is permanent.
                        $diagPath = "/providers/microsoft.aadiam/diagnosticSettings/${diagSettingName}?api-version=2017-04-01-preview"
                        $diagResponse = Invoke-AzRestMethod -Path $diagPath -Method PUT -Payload $diagPayload
                        if ($diagResponse.StatusCode -in 200, 201) {
                            $graphDiagSettingEnabled = $true
                            Write-Success "  Graph activity logging enabled → workspace; data will begin flowing (forward-only)."
                        } else {
                            Write-Warn "  Entra diagnostic setting PUT returned HTTP $($diagResponse.StatusCode). Common causes: missing Entra P1/P2 (category rejected by the service) or insufficient rights (Security Administrator / Global Administrator required). Response: $($diagResponse.Content)"
                            $consentFailures += "Entra diagnostic setting 'PAA-GraphActivityLogs' (MicrosoftGraphActivityLogs → workspace) — HTTP $($diagResponse.StatusCode)"
                        }
                    } catch {
                        Write-Warn "  Entra diagnostic setting creation failed: $($_.Exception.Message). Common causes: missing Entra P1/P2 licence or insufficient Entra admin rights."
                        $consentFailures += "Entra diagnostic setting 'PAA-GraphActivityLogs' (MicrosoftGraphActivityLogs → workspace) — $($_.Exception.Message)"
                    }
                } else {
                    Write-Host "  Graph activity log stream skipped (not confirmed)." -ForegroundColor Gray
                }
            }
        }
    }
} else {
    Write-Host "  Skipped (use -IncludeLogAnalytics to configure)." -ForegroundColor Gray
    Write-Host "  Note: -PermissionsOnly also suppresses this step — to (re)grant the workspace role, re-run without -PermissionsOnly." -ForegroundColor Gray
}

# ---------------------------------------------------------------------------
# Step 5 — Optional Defender CSPM
# ---------------------------------------------------------------------------

$defenderAppId = $null
$defenderSecretText = $null
$defenderSpName = $null

Write-Step "[5/5] Defender CSPM service principal..."

if ($IncludeDefenderCspm -and -not $certMode) {
    # Certificate mode refuses -IncludeDefenderCspm before signing in; the condition says so too.
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

        # same treatment as the Azure SP above — assign, then confirm by reading it back.
        $defenderRoleResults = @()
        foreach ($sub in $subscriptions) {
            $scope = "/subscriptions/$($sub.Id)"
            Write-Host "    Assigning Security Reader (Defender) on $($sub.Name)..." -ForegroundColor Gray
            $defenderRoleResults += Grant-AzureRoleVerified -ObjectId $defenderSp.Id `
                -RoleDefinitionId $securityReaderRoleId -RoleName 'Security Reader (Defender)' `
                -Scope $scope -SubscriptionName $sub.Name
        }

        $defenderFailed = @($defenderRoleResults | Where-Object { $_.Outcome -eq 'Failed' })
        if ($defenderFailed.Count -gt 0) {
            Write-Warn "  $($defenderFailed.Count) Defender role assignment(s) could NOT be confirmed:"
            foreach ($f in $defenderFailed) {
                Write-Warn "    - $($f.Subscription) — $($f.Reason)"
            }
            Write-Warn "  Defender CSPM data for those subscriptions will be unavailable to PAA."
        }

        $defenderAppId = $defenderSp.AppId

        # Bootstrap-only secret: PAA discards it after provisioning a self-rotating certificate.
        # Short-lived ($bootstrapSecretDays-day) — NOT a long-lived credential. Skipped in -PermissionsOnly.
        # Certificate mode refuses -IncludeDefenderCspm before signing in; the guard says so here too.
        if (-not $PermissionsOnly -and -not $certMode) {
            $defenderSecretExpiry = (Get-Date).AddDays($bootstrapSecretDays)
            $defenderSecret = New-AzADAppCredential -ApplicationId $defenderSp.AppId -StartDate (Get-Date) -EndDate $defenderSecretExpiry
            $defenderSecretText = $defenderSecret.SecretText
        }

        # Same self-managed cert bootstrap as the Azure SP. The Connect-MgGraph
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
    if ($AzureOnly) {
        Write-Host "  M365 app          : not created (-AzureOnly)"
        Write-Host "  Re-applied        : Azure roles (Reader/Security Reader/Cost Mgmt Reader);"
        Write-Host "                      self-managed cert ownership. No Graph/Exchange/SharePoint/"
        Write-Host "                      Power BI/Global Reader/Power Platform grants."
    } else {
        Write-Host "  M365 app          : $m365AppName ($m365AppId)"
        Write-Host "  Re-applied        : Azure roles (Reader/Security Reader/Cost Mgmt Reader);"
        Write-Host "                      Graph app roles + Exchange.ManageAsApp + Sites.FullControl.All"
        Write-Host "                      + Tenant.Read.All (Power BI) + Global Reader; Power Platform"
        Write-Host "                      management-app registration (BAP); self-managed cert ownership."
    }
    if ($IncludeDefenderCspm -and $defenderAppId) {
        Write-Host "  Defender SP       : $defenderSpName ($defenderAppId) — Security Reader re-applied"
    }
    if ($consentFailures.Count -gt 0) {
        Write-Host ""
        Write-Host "  ACTION REQUIRED — grant these manually (admin consent in the Azure portal):" -ForegroundColor DarkYellow
        Write-Host "  https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/CallAnAPI/appId/$(if ($AzureOnly) { $azAppId } else { $m365AppId })/isMSAApp/" -ForegroundColor DarkYellow
        $consentFailures | ForEach-Object { Write-Host "    - $_" -ForegroundColor DarkYellow }
    }
    Write-Host ""
    if (-not $AzureOnly) {
        Write-Host "  Power BI / Fabric (CIS §9): also enable 'Service principals can use read-only" -ForegroundColor Gray
        Write-Host "  Power BI admin APIs' in the Power BI admin portal (manual, one-time)." -ForegroundColor Gray
        Write-Host ""
    }
    Write-Success "Permissions-only run complete. No credentials file written (existing cert auth unchanged)."
    return
}

# ---------------------------------------------------------------------------
# Certificate mode: no secret was created, so there is no credentials file.
# Print what still needs an admin, then the four values PAA needs, and stop before the
# credentials block. A thumbprint is printed only after Complete-PaaCertModeApp read it back
# from the app registration. Copy C2 and C3 are approved verbatim.
# ---------------------------------------------------------------------------

if ($certMode) {
    # Consent failures were listed under ACTION REQUIRED in Step 3, as in the secret mode.
    Write-Host ""
    Write-Host "  Power BI / Fabric (CIS §9): also enable 'Service principals can use read-only" -ForegroundColor Gray
    Write-Host "  Power BI admin APIs' in the Power BI admin portal (manual, one-time)." -ForegroundColor Gray
    Write-Host ""

    # Owners last, and only when both certificates are confirmed: each service principal is left with
    # no owner but itself, then each app's own service principal becomes its only owner. The first
    # failure stops both loops, so no later target loses its owners and the C2 rollback below runs
    # while the signed-in admin still owns every app it has not yet reached. Only the app-owner step
    # takes the admin off an app, so it comes last. A failure fails that target (C2) like an
    # unconfirmed certificate.
    if ($m365CertConfirmed -and $azureCertConfirmed) {
        $ownerTargets = @(
            @{ Label = 'Azure'; App = $azSp.ApplicationObjectId; Sp = $azSp.Id },
            @{ Label = 'M365'; App = $m365App.Id; Sp = $m365Sp.Id })
        $ownerFailure = $null
        foreach ($target in $ownerTargets) {
            if (-not (Set-PaaServicePrincipalOwnedOnlyBySelf -ServicePrincipalId $target.Sp -Label $target.Label)) { $ownerFailure = $target; break }
        }
        if (-not $ownerFailure) {
            foreach ($target in $ownerTargets) {
                if (-not (Set-PaaServicePrincipalAsOnlyOwner -ApplicationObjectId $target.App -ServicePrincipalId $target.Sp -Label $target.Label)) { $ownerFailure = $target; break }
            }
        }
        if ($ownerFailure) {
            if ($ownerFailure.Label -eq 'Azure') { $azureCertConfirmed = $false } else { $m365CertConfirmed = $false }
        }
    }

    $unconfirmedApps = @()
    if (-not $m365CertConfirmed) { $unconfirmedApps += $m365AppName }
    if (-not $azureCertConfirmed) { $unconfirmedApps += $azSpName }
    if ($unconfirmedApps.Count -gt 0) {
        foreach ($app in $unconfirmedApps) {
            Write-Host "Could not confirm the certificate on $app. No thumbprint is printed for it; re-run the command." -ForegroundColor Red
        }
        # The re-run C2 asks for starts clean: this run's new app registrations are removed, reused ones are left.
        $undo = Undo-PaaCertModeCreatedApps -Created $certCreatedApps -Subscriptions $subscriptions
        if (-not $undo.AllRemoved) {
            Write-Host "ERROR: Certificate setup stopped, but these app registrations this run created could not be removed: $($undo.NotRemoved -join ', '). Delete them in the Microsoft Entra admin center under App registrations." -ForegroundColor Red
        }
        exit 1
    }

    Write-Success "Certificate mode complete. No client secret was created. Paste these four values into PAA:"
    Write-Host "M365_CLIENT_ID: $m365AppId"
    Write-Host "M365_CERT_THUMBPRINT: $($m365Cert.Thumbprint)"
    Write-Host "AZURE_CLIENT_ID: $azAppId"
    Write-Host "AZURE_CERT_THUMBPRINT: $($azureCert.Thumbprint)"
    Write-Host ""
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
if ($AzureOnly) {
    $credLines += "# -- Microsoft 365 / Graph --"
    $credLines += "# NOT ONBOARDED: this tenant was onboarded with -AzureOnly. No M365 app registration"
    $credLines += "# exists, no Graph application permission was requested, and no Exchange, SharePoint,"
    $credLines += "# Power BI, Global Reader or Power Platform grant was made. Leave the Microsoft 365"
    $credLines += "# section in PAA > Settings > Integrations empty. M365, Entra ID and Zero Trust checks"
    $credLines += "# will report as not evaluated until a separate onboarding grants that access."
    $credLines += ""
} else {
    $credLines += "# -- M365 / Graph App Registration --"
    $credLines += "M365_TENANT_ID=$TenantId"
    $credLines += "M365_APP_NAME=$m365AppName"
    $credLines += "M365_CLIENT_ID=$m365AppId"
    $credLines += "M365_CLIENT_SECRET=*** see below ***"
    $credLines += ""
}

if ($logAnalyticsWorkspaceId) {
    $credLines += "# -- Log Analytics --"
    $credLines += "LOG_ANALYTICS_WORKSPACE_ID=$logAnalyticsWorkspaceId"
    if ($workspaceArmId) {
        $credLines += "# Workspace ARM ID     : $workspaceArmId"
        $credLines += "# Log Analytics Reader : $(if ($workspaceRoleGranted) { 'Granted to Azure SP' } else { 'Not granted (see warnings above)' })"
        $credLines += "# Graph activity logs  : $(if ($graphDiagSettingEnabled) { 'Enabled (PAA-GraphActivityLogs diagnostic setting created)' } else { 'Not enabled' })"
    } else {
        $credLines += "# Workspace ARM ID     : Could not be resolved — Log Analytics Reader was not granted"
    }
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
if (-not $AzureOnly) {
    $credLines += "M365_CLIENT_SECRET=$m365SecretText"
}

if ($IncludeDefenderCspm -and $defenderSecretText) {
    $credLines += "DEFENDER_CLIENT_SECRET=$defenderSecretText"
}

$credLines += ""
$credLines += "# ============================================================"
$credLines += "#  PERMISSIONS GRANTED"
$credLines += "# ============================================================"
$credLines += "# Azure SP roles: Reader, Security Reader, Cost Management Reader (on all listed subscriptions)"
$credLines += "# Azure SP Graph: Application.ReadWrite.OwnedBy (self-scoped) + owner of its own"
$credLines += "#                 app registration (self-rotating certificate)."
if ($AzureOnly) {
    $credLines += "# M365 permissions: NONE — onboarded with -AzureOnly."
    $credLines += "#   No Graph application permission, no Exchange.ManageAsApp, no Sites.FullControl.All,"
    $credLines += "#   no Power BI Tenant.Read.All, no Global Reader directory role, and no Power Platform"
    $credLines += "#   management-app registration was requested or granted. The only permission this"
    $credLines += "#   onboarding holds outside Azure RBAC is the self-scoped Application.ReadWrite.OwnedBy"
    $credLines += "#   above, which manages this principal's own certificate and nothing else."
} else {
    $credLines += "# M365 permissions (application/Role):"
    $requiredGraphPermissions | ForEach-Object { $credLines += "#   - $_" }
    $credLines += "#   - Exchange.ManageAsApp (Office 365 Exchange Online)"
    $credLines += "#   - Sites.FullControl.All (SharePoint Online — PnP / Get-PnPTenant)"
    $credLines += "#   - Tenant.Read.All (Power BI Service — CIS Section 9)"
    $credLines += "#   - Directory role: Global Reader"
    $credLines += "#   - Power Platform management app registration (BAP — SCUBA-PP / MT.109x)"
    $credLines += "# MANUAL STEP STILL REQUIRED for Power BI / Microsoft Fabric checks (CIS Section 9):"
    $credLines += "#   the 'Tenant.Read.All' app role above is granted, but a Power BI/Fabric Service Admin"
    $credLines += "#   must ALSO enable 'Service principals can use read-only Power BI admin APIs' in the"
    $credLines += "#   Power BI admin portal (Tenant settings). Without it the Admin API returns 401."
    $credLines += "# POWER PLATFORM (SCUBA-PP / MT.109x): the script registers this app as a Power"
    $credLines += "#   Platform management app via the BAP REST API, which requires the person RUNNING this"
    $credLines += "#   script to be a Power Platform Administrator / Global Administrator. If that step warned"
    $credLines += "#   above, register it manually in Windows PowerShell 5.1 as a PP admin:"
    $credLines += "#     New-PowerAppManagementApp -ApplicationId $m365AppId"
    $credLines += "#   Without it the BAP admin API returns 403 and PP checks stay ManualReview."
}
$credLines += "# NOTE: ALL client secrets below (Azure$(if (-not $AzureOnly) { ', M365' })$(if ($IncludeDefenderCspm) { ', Defender' })) are bootstrap-only"
$credLines += "#       ($bootstrapSecretDays-day expiry) and are discarded by PAA after it provisions a"
$credLines += "#       self-rotating certificate on each service principal."

if ($IncludeDefenderCspm) {
    $credLines += "# Defender SP roles: Security Reader (on all listed subscriptions)"
    $credLines += "# Defender SP Graph: Application.ReadWrite.OwnedBy (self-scoped) + owner of its"
    $credLines += "#                    own app registration (self-rotating certificate)."
}

$credLines += ""
$credLines += "# ============================================================"
$credLines += "#  NEXT STEPS"
$credLines += "# ============================================================"
$credLines += "# 1. Open PAA app and go to Settings > Integrations"
$credLines += "# 2. Enter Azure credentials (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)"
if ($AzureOnly) {
    $credLines += "# 3. Leave the Microsoft 365 section empty — this tenant is Azure-only."
} else {
    $credLines += "# 3. Enter M365 credentials (M365_CLIENT_ID, M365_CLIENT_SECRET, M365_TENANT_ID)"
    $credLines += "#    (Power BI / Fabric checks) the 'Tenant.Read.All' app role is already granted;"
    $credLines += "#    enable 'service principals can use read-only Power BI admin APIs' in the Power BI"
    $credLines += "#    admin portal to activate CIS Section 9 — see PERMISSIONS GRANTED above."
}

if ($consentFailures.Count -gt 0) {
    $credLines += "# 4. REQUIRED: Grant admin consent in the Azure portal:"
    $credLines += "#    https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/CallAnAPI/appId/$(if ($AzureOnly) { $azAppId } else { $m365AppId })/isMSAApp/"
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
if ($AzureOnly) {
    Write-Host "  Microsoft 365          : not onboarded (-AzureOnly)" -ForegroundColor Cyan
    Write-Host "    No app registration, no Graph permission, no Global Reader." -ForegroundColor Gray
    Write-Host "    M365 / Entra ID / Zero Trust checks will report as not evaluated." -ForegroundColor Gray
} else {
    Write-Host "  M365 Graph App Registration" -ForegroundColor Cyan
    Write-Host "    Name                 : $m365AppName"
    Write-Host "    Client ID (App ID)   : $m365AppId"
    Write-Host "    Client Secret        : $(Get-MaskedSecret $m365SecretText)"
}

if ($logAnalyticsWorkspaceId) {
    Write-Host ""
    Write-Host "  Log Analytics" -ForegroundColor Cyan
    Write-Host "    Workspace ID         : $logAnalyticsWorkspaceId"
    if ($workspaceArmId) {
        Write-Host "    Workspace ARM ID     : $workspaceArmId" -ForegroundColor Gray
        Write-Host "    Log Analytics Reader : $(if ($workspaceRoleGranted) { 'Granted to Azure SP' } else { 'Not granted (see warnings above)' })" -ForegroundColor $(if ($workspaceRoleGranted) { 'Green' } else { 'DarkYellow' })
        Write-Host "    Graph activity logs  : $(if ($graphDiagSettingEnabled) { 'Enabled (PAA-GraphActivityLogs)' } else { 'Not enabled' })" -ForegroundColor $(if ($graphDiagSettingEnabled) { 'Green' } else { 'Gray' })
    } else {
        Write-Host "    Workspace ARM ID     : Could not be resolved — Log Analytics Reader was not granted" -ForegroundColor DarkYellow
    }
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
Write-Host "  All secrets are bootstrap-only ($bootstrapSecretDays-day expiry) — PAA replaces each with a" -ForegroundColor DarkYellow
Write-Host "  self-rotating certificate and discards the secret." -ForegroundColor DarkYellow
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
