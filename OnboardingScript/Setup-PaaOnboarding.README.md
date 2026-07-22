# Setup-PaaOnboarding.ps1

## What this script does

Automates the PAA tenant onboarding that would otherwise require several manual steps in the Azure and Entra ID portals. It creates:

- an **Azure service principal** with read-only access to your subscriptions (plus cost analytics),
- an **M365 (Microsoft Graph) app registration** with the application permissions PAA needs,
- and, optionally, a **Defender CSPM service principal** and a Log Analytics workspace reference.

Each principal is created with a short-lived **bootstrap secret only**. After you connect it, PAA provisions a **self-rotating certificate** in its own Key Vault and discards the bootstrap secret — so there is no long-lived credential to manage or rotate (R-618 / R-619). At the end the script writes the bootstrap credentials to a locked `.txt` file in the same folder, ready to paste into PAA.

## Prerequisites

**PowerShell 7 or later** is required.

Required modules:

```powershell
Install-Module -Name Az.Accounts, Az.Resources, Microsoft.Graph -Scope CurrentUser -Force
```

**Required admin roles in the target tenant:**

- Global Administrator or Application Administrator (to create app registrations and grant admin consent)
- Owner or User Access Administrator on each Azure subscription (to assign RBAC roles)

## Usage examples

**Basic — Azure scanning and M365 checks only:**

```powershell
.\Setup-PaaOnboarding.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

**Specific subscription IDs (skip auto-discovery):**

```powershell
.\Setup-PaaOnboarding.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -SubscriptionIds @("11111111-aaaa-bbbb-cccc-000000000001", "22222222-aaaa-bbbb-cccc-000000000002")
```

**With Log Analytics workspace (prompts for workspace ID; also grants Log Analytics Reader on the workspace to the Azure SP):**

```powershell
.\Setup-PaaOnboarding.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -IncludeLogAnalytics
```

**With Log Analytics workspace and Entra Graph activity log stream (R-671 app-permission right-sizing):**

```powershell
.\Setup-PaaOnboarding.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -IncludeLogAnalytics `
    -EnableGraphActivityLogs
```

**Full setup including Defender CSPM:**

```powershell
.\Setup-PaaOnboarding.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -IncludeLogAnalytics `
    -EnableGraphActivityLogs `
    -IncludeDefenderCspm
```

**Re-apply permissions only (existing apps, no new secrets):**

```powershell
.\Setup-PaaOnboarding.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -PermissionsOnly
```

Use `-PermissionsOnly` to grant **newly-added** permissions to a tenant that was **already onboarded** — for example after the SharePoint `Sites.FullControl.All`, Power BI `Tenant.Read.All`, Global Reader, or the Power Platform management-app registration were added to the script (R-613). It:

- **requires the existing** `PAA-Azure-…` and `PAA-M365-…` principals (errors instead of creating them),
- re-applies **all** Azure roles, Graph/Exchange/SharePoint/Power BI app-role consents, the Global Reader directory role, and the Power Platform management-app registration (every grant is idempotent),
- **generates no client secret and writes no credentials file** (the apps already authenticate via their self-rotating certificate — existing cert auth is untouched).

Add `-IncludeDefenderCspm` to also re-apply the Defender CSPM principal's roles (it must already exist). Any grant that needs manual portal consent is listed at the end, same as a full run.

## What gets created

### Azure service principal
Named `PAA-Azure-<first 8 chars of tenant ID>`, assigned the following **read-only** roles on every in-scope subscription:

- **Reader** — resource inventory and configuration
- **Security Reader** — Microsoft Defender for Cloud posture, security alerts, regulatory-compliance data
- **Cost Management Reader** — cost analytics (Reader's `*/read` does **not** cover the Cost Management query action, so this is required for cost intelligence)

It is also made the **owner of its own app registration** and granted the self-scoped `Application.ReadWrite.OwnedBy` Graph role, so PAA can replace the bootstrap secret with a self-rotating certificate.

### M365 (Microsoft Graph) app registration
Named `PAA-M365-<first 8 chars of tenant ID>`, with the following Graph **application** permissions, admin-consented automatically where possible. All are read-only except `Application.ReadWrite.OwnedBy`, which is self-scoped (it manages only this app's own credential):

- `Directory.Read.All` — directory objects: roles, users, service principals, apps, groups, organisation, domains
- `Policy.Read.All` — Conditional Access, authentication-method, authorization, cross-tenant-access, and app-management policies
- `RoleManagement.Read.Directory` — PIM schedules and role-management policies
- `AccessReview.Read.All` — access-review definitions/instances (P2)
- `DelegatedAdminRelationship.Read.All` — GDAP partner relationships
- `DelegatedPermissionGrant.Read.All` — OAuth2 delegated grants
- `IdentityRiskyUser.Read.All` — Identity Protection risky users (P2)
- `AuditLog.Read.All` — sign-in activity on guest users
- `Reports.Read.All` — assigned-but-inactive M365 licence detection (optional; degrades gracefully if absent)
- `DeviceManagementManagedDevices.Read.All`, `DeviceManagementConfiguration.Read.All`, `DeviceManagementApps.Read.All` — Intune device compliance, configuration, and app-protection
- `SecurityEvents.Read.All` — Defender alerts, Secure Score, and Defender for Office 365 policies
- `SecurityIncident.Read.All` — Defender incidents
- `SharePointTenantSettings.Read.All` — SharePoint / OneDrive admin settings
- `Application.ReadWrite.OwnedBy` — self-scoped certificate bootstrap/rotation (this app only)

Plus:

- **`Exchange.ManageAsApp`** (Office 365 Exchange Online app role) — Exchange Online configuration collection
- **`Sites.FullControl.All`** (SharePoint Online app role) — SharePoint/OneDrive deep config (R-613 PnP)
- **`Tenant.Read.All`** (Power BI Service app role) — CIS Section 9 (also needs the manual portal toggle below)
- **Global Reader** directory role — read-only access to admin surfaces collected via PowerShell
- **Power Platform management application** (BAP registration) — Power Platform tenant settings + DLP (R-613 SCUBA-PP / MT.109x)

### Power Platform — registration requires a Power Platform Admin running this script
The Power Platform checks (SCUBA-PP-1.1/1.2/2.1/4.1, MT.1099/1100/1101) read tenant settings + DLP policies from the BAP admin REST API. The script registers the M365 app as a **Power Platform management application** (the REST equivalent of `New-PowerAppManagementApp`, since that cmdlet is Windows-PowerShell-5.1-only). This call needs a **signed-in admin user** who holds **Power Platform Administrator / Global Administrator** (`ManageAdminApplications`) — i.e. whoever runs this script. If it warns, register manually in **Windows PowerShell 5.1** as a PP admin: `New-PowerAppManagementApp -ApplicationId <M365_CLIENT_ID>`. Without it the BAP API returns 403 and the PP checks stay ManualReview (safe).

### Power BI / Microsoft Fabric — manual grant
The CIS Section 9 (Power BI / Fabric) checks need **`Tenant.Read.All`** granted to the M365 app **in the Power BI admin portal** (Admin API settings → service-principal access). This is a Power BI service permission, not a Graph app role, so the script cannot grant it — do it manually if you want those checks. They are skipped gracefully if it is absent.

### Credentials file
`paa-credentials-<tenant prefix>.txt` in the scripts folder, restricted to your Windows user account only. It contains **bootstrap secrets (7-day expiry)** — delete it after you have pasted the values into PAA.

### (Optional) Log Analytics workspace

When `-IncludeLogAnalytics` is set, the script:

1. Prompts for the **Log Analytics Workspace ID** (GUID from Azure portal > Log Analytics workspace > Overview).
2. Resolves the workspace's **ARM resource ID** via Azure Resource Graph.
3. Assigns **Log Analytics Reader** (`73c42c96-874c-492b-b04d-ab87d138a893`) on the workspace to the Azure service principal — so PAA can query the workspace even if it lives in a subscription not covered by the scan scope.

One workspace serves both features:

| Table | Feature |
|-------|---------|
| `AzureActivity` | IAM Usage Visualizer |
| `MicrosoftGraphActivityLogs` | R-671 App-Permission Right-Sizing |

#### `-EnableGraphActivityLogs` — Entra Graph activity log stream

Add `-EnableGraphActivityLogs` (together with `-IncludeLogAnalytics`) to also create an Entra ID diagnostic setting (`PAA-GraphActivityLogs`) that streams the `MicrosoftGraphActivityLogs` category to the workspace. The script shows a confirmation prompt before applying it because:

- **Requires Entra ID P1 or P2 licence** — the category is rejected by the Entra service without it.
- **Incurs Log Analytics ingestion cost** — it streams ALL tenant Graph API traffic continuously.
- **Forward-only** — there is no backfill. Data starts accumulating from the moment the setting is created. Allow **30-90 days** before the R-671 app-permission right-sizing recommendations become meaningful.

The setting uses the stable name `PAA-GraphActivityLogs`, so re-running the script with `-EnableGraphActivityLogs` is idempotent (it updates rather than duplicates).

If the workspace ARM ID cannot be resolved (bad GUID, or the admin running the script does not have Reader access to the workspace's subscription), the role grant and diagnostic setting are skipped with a warning, but the workspace ID is still recorded in the credentials file.

### (Optional) Defender CSPM service principal
Named `PAA-Defender-<first 8 chars of tenant ID>`, assigned **Security Reader** on all subscriptions, with the same self-rotating-certificate model as the Azure principal.

## After running

1. Open the credentials file (`paa-credentials-<tenant prefix>.txt`) in the scripts folder.
2. In PAA, go to **Settings > Integrations**.
3. Under **Azure**, paste `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`, and `AZURE_SUBSCRIPTION_IDS`.
4. Under **Microsoft 365**, paste `M365_CLIENT_ID`, `M365_CLIENT_SECRET`, and `M365_TENANT_ID`.
5. *(Optional)* For Power BI / Fabric checks, grant `Tenant.Read.All` to the M365 app in the Power BI admin portal (see above).
6. If you added Log Analytics, paste `LOG_ANALYTICS_WORKSPACE_ID` in the Log Analytics section.
7. If you added Defender CSPM, paste `DEFENDER_CLIENT_ID` and `DEFENDER_CLIENT_SECRET` in the Defender section.
8. Click **Validate** next to each connection. On first validation PAA provisions a self-rotating certificate for each principal and stops using the bootstrap secret.
9. Run your first scan from the assessments page.
10. Delete the credentials file immediately after — it contains live (if short-lived) secrets:
    ```powershell
    Remove-Item "scripts\paa-credentials-<tenant prefix>.txt"
    ```

## If admin consent fails

The script attempts to grant admin consent programmatically. If it cannot (typically due to Conditional Access or Privileged Identity Management restrictions), it prints a warning and a direct portal URL.

To grant consent manually:

1. Open the printed URL, or go to **Entra ID portal > App registrations > `PAA-M365-<tenant prefix>` > API permissions**.
2. Click **Grant admin consent for `<your tenant>`**.
3. Confirm. All listed permissions should show a green checkmark.

PAA cannot collect M365 data for any permission that has not been consented.

## Re-running the script

The script is idempotent. If `PAA-Azure-<tenant prefix>`, `PAA-M365-<tenant prefix>`, or `PAA-Defender-<tenant prefix>` already exist in Entra ID, they are reused rather than recreated, and existing role assignments/consents are left in place. A fresh **bootstrap** secret (7-day expiry) is issued on each run; because PAA rotates each principal onto its own certificate after connection, these bootstrap secrets are disposable — you do not need to track or clean them up beyond deleting the credentials file.
