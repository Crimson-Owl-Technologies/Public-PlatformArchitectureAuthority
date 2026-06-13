# Setup-PaaOnboarding.ps1

## What this script does

Automates the PAA tenant onboarding process that would otherwise require five manual steps in the Azure and Entra ID portals. It creates an Azure service principal with read-only access to your subscriptions, an M365 app registration with the Graph API permissions PAA needs, and optionally a Defender CSPM principal and Log Analytics workspace reference. At the end it writes all credentials to a locked `.txt` file in the same folder, ready to paste into PAA.

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

**With Log Analytics workspace (prompts for workspace ID):**

```powershell
.\Setup-PaaOnboarding.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -IncludeLogAnalytics
```

**Full setup including Defender CSPM:**

```powershell
.\Setup-PaaOnboarding.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -IncludeLogAnalytics `
    -IncludeDefenderCspm
```

## What gets created

- **Azure service principal** named `PAA-Azure-<first 8 chars of tenant ID>`, assigned Reader and Security Reader on every in-scope subscription, with a 2-year client secret
- **M365 app registration** named `PAA-M365-<first 8 chars of tenant ID>` with the following Graph application permissions, admin-consented automatically where possible:
  - `Policy.Read.All`, `RoleManagement.Read.Directory`, `Directory.Read.All`, `Application.Read.All`
  - `DeviceManagementManagedDevices.Read.All`, `DeviceManagementConfiguration.Read.All`, `DeviceManagementApps.Read.All`
  - `SecurityEvents.Read.All`, `Reports.Read.All`, `Organization.Read.All`
  - `IdentityRiskyUser.Read.All`, `DelegatedPermissionGrant.Read.All`, `AuditLog.Read.All`
  - `UserAuthenticationMethod.Read.All`, `CrossTenantInformation.ReadBasic.All`
  - `SharePointTenantSettings.Read.All`, `TeamworkDevice.Read.All`
- **Credentials file** (`paa-credentials-<tenant prefix>.txt`) in the scripts folder, restricted to your Windows user account only
- *(Optional)* **Defender CSPM service principal** named `PAA-Defender-<first 8 chars of tenant ID>`, assigned Security Reader on all subscriptions, with its own 2-year client secret

## After running

1. Open the credentials file (`paa-credentials-<tenant prefix>.txt`) in the scripts folder.
2. In PAA, go to **Settings > Integrations**.
3. Under **Azure**, paste `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`, and `AZURE_SUBSCRIPTION_IDS`.
4. Under **Microsoft 365**, paste `M365_CLIENT_ID`, `M365_CLIENT_SECRET`, and `M365_TENANT_ID`.
5. If you added Log Analytics, paste `LOG_ANALYTICS_WORKSPACE_ID` in the Log Analytics section.
6. If you added Defender CSPM, paste `DEFENDER_CLIENT_ID` and `DEFENDER_CLIENT_SECRET` in the Defender section.
7. Click **Validate** next to each connection to confirm PAA can authenticate.
8. Run your first scan from the assessments page.
9. Delete the credentials file immediately after — it contains live secrets:
   ```powershell
   Remove-Item "scripts\paa-credentials-<tenant prefix>.txt"
   ```

## If admin consent fails

The script attempts to grant admin consent programmatically. If it cannot (typically due to Conditional Access or Privileged Identity Management restrictions), it will print a warning and a direct portal URL.

To grant consent manually:

1. Open the printed URL, or go to **Entra ID portal > App registrations > `PAA-M365-<tenant prefix>` > API permissions**.
2. Click **Grant admin consent for `<your tenant>`**.
3. Confirm. All listed permissions should show a green checkmark.

PAA will not be able to collect M365 data for any permission that has not been consented.

## Re-running the script

The script is idempotent. If `PAA-Azure-<tenant prefix>` or `PAA-M365-<tenant prefix>` already exist in Entra ID, they are reused rather than recreated. A new client secret is added on each run regardless, so keep track of which secret is current. Old secrets can be removed from **Entra ID > App registrations > Certificates & secrets**.
