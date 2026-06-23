#requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Groups, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Identity.Governance

<#
.SYNOPSIS
    Creates a role-assignable security group (SG_PIM_<RoleName>) for every
    built-in Entra ID directory role and makes each group eligible for its
    role via PIM.

.DESCRIPTION
    Requires Entra ID P2 (PIM) and a caller with Privileged Role Administrator
    or Global Administrator. Role-assignable groups can only be managed by
    those roles and count against the 500-group tenant cap.

.PARAMETER GroupPrefix
    Prefix for created groups. Default: "SG_PIM_".

.PARAMETER EligibilityDurationDays
    Days the eligibility lasts. 0 = permanent (no expiration). Default: 0.

.PARAMETER Justification
    Justification recorded on each PIM eligibility request.

.EXAMPLE
    .\Set-PimGroupsForPrivilegedRoles.ps1 -WhatIf
    Shows everything it would create without making changes.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]   $GroupPrefix             = 'SG_PIM_',
    [int]      $EligibilityDurationDays = 0,
    [string]   $Justification           = 'Automated PIM enablement for directory role'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# --- Connect -----------------------------------------------------------------
$scopes = @(
    'RoleManagement.ReadWrite.Directory'  # read role defs + write eligibility
    'Group.ReadWrite.All'                 # create role-assignable groups
)
$ctx = Get-MgContext
if (-not $ctx -or ($scopes | Where-Object { $_ -notin $ctx.Scopes })) {
    Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor Cyan
    Connect-MgGraph -Scopes $scopes -NoWelcome
}

# --- Helpers -----------------------------------------------------------------
function Get-SafeMailNickname {
    param([string]$Name)
    # mailNickname must be alphanumeric (no spaces / special chars)
    $clean = ($Name -replace '[^a-zA-Z0-9]', '')
    if ([string]::IsNullOrWhiteSpace($clean)) { $clean = "role$([guid]::NewGuid().ToString('N').Substring(0,8))" }
    "$($GroupPrefix -replace '[^a-zA-Z0-9]', '')$clean"
}

function Wait-ForGroup {
    param([string]$GroupId, [int]$TimeoutSeconds = 120)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    do {
        try { if (Get-MgGroup -GroupId $GroupId -ErrorAction Stop) { return $true } } catch { }
        Start-Sleep -Seconds 5
    } while ($sw.Elapsed.TotalSeconds -lt $TimeoutSeconds)
    return $false
}

function Invoke-WithRetry {
    # Retries through replication lag: a freshly created group is not yet a known
    # 'subject' to the role-management service, so PIM requests return 404
    # SubjectNotFound for a short window after creation.
    param(
        [Parameter(Mandatory)] [scriptblock] $Action,
        [int] $TimeoutSeconds = 300,
        [int] $DelaySeconds   = 15
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        try { return & $Action }
        catch {
            $msg = $_.Exception.Message
            $transient = $msg -match 'SubjectNotFound|not found|429|throttl'
            if (-not $transient -or $sw.Elapsed.TotalSeconds -ge $TimeoutSeconds) { throw }
            Write-Host ("    waiting for replication ({0}s elapsed)..." -f [int]$sw.Elapsed.TotalSeconds) -ForegroundColor DarkYellow
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

# Implicit / default roles that Entra applies automatically. They cannot be
# assigned to a principal (PIM returns 400 "implicit user roles ... not supported"),
# so we skip them entirely rather than create orphan groups for them.
$ImplicitRoleNames = @(
    'User'
    'Guest User'
    'Restricted Guest User'
    'Workplace Device Join'
    'Device Join'
    'Authenticated Users'
)

# --- 1. Role definitions (all built-in directory roles) ----------------------
Write-Host 'Fetching all built-in directory role definitions...' -ForegroundColor Cyan
$roles = Get-MgRoleManagementDirectoryRoleDefinition -All |
    Where-Object { $_.IsBuiltIn -eq $true -and $_.DisplayName -notin $ImplicitRoleNames }

if (-not $roles) { throw 'No role definitions returned. Check permissions / P2 licensing.' }
Write-Host ("Found {0} assignable roles (implicit roles excluded)." -f $roles.Count) -ForegroundColor Green

# Pre-load existing groups once (avoids per-role lookup throttling)
$existingGroups = @{}
Get-MgGroup -Filter "startswith(displayName,'$GroupPrefix')" -All |
    ForEach-Object { $existingGroups[$_.DisplayName] = $_ }

$results = [System.Collections.Generic.List[object]]::new()

foreach ($role in $roles) {
    $displayName   = "$GroupPrefix$(($role.DisplayName) -replace '\s', '')"
    $mailNickname  = Get-SafeMailNickname -Name $role.DisplayName
    $status        = [ordered]@{ Role = $role.DisplayName; Group = $displayName; GroupId = $null; Action = '' }

    try {
        # --- 2. Group (create if missing) ------------------------------------
        $group = $existingGroups[$displayName]
        if (-not $group) {
            if ($PSCmdlet.ShouldProcess($displayName, 'Create role-assignable security group')) {
                $group = New-MgGroup -DisplayName $displayName `
                                     -Description "PIM eligibility group for the '$($role.DisplayName)' Entra role." `
                                     -MailEnabled:$false `
                                     -SecurityEnabled:$true `
                                     -MailNickname $mailNickname `
                                     -IsAssignableToRole:$true
                [void](Wait-ForGroup -GroupId $group.Id)
                $status.Action = 'Created group'
            } else { $status.Action = 'WhatIf: would create group'; $results.Add([pscustomobject]$status); continue }
        } else {
            $status.Action = 'Group exists'
        }
        $status.GroupId = $group.Id

        # --- 3. PIM eligibility (skip if already present) --------------------
        $existingElig = Get-MgRoleManagementDirectoryRoleEligibilitySchedule `
            -Filter "principalId eq '$($group.Id)' and roleDefinitionId eq '$($role.Id)'" -ErrorAction SilentlyContinue
        if ($existingElig) {
            $status.Action += '; eligibility already set'
            $results.Add([pscustomobject]$status); continue
        }

        $expiration = if ($EligibilityDurationDays -le 0) {
            @{ type = 'noExpiration' }
        } else {
            @{ type = 'afterDuration'; duration = "P$($EligibilityDurationDays)D" }
        }

        $params = @{
            Action           = 'adminAssign'
            PrincipalId      = $group.Id
            RoleDefinitionId = $role.Id
            DirectoryScopeId = '/'
            Justification    = $Justification
            ScheduleInfo     = @{
                StartDateTime = (Get-Date).ToUniversalTime().ToString('o')
                Expiration    = $expiration
            }
        }

        if ($PSCmdlet.ShouldProcess("$displayName -> $($role.DisplayName)", 'Create PIM eligible assignment')) {
            Invoke-WithRetry -Action {
                [void](New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $params)
            } | Out-Null
            $status.Action += '; eligibility created'
        } else {
            $status.Action += '; WhatIf: would create eligibility'
        }
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match 'implicit user roles|is not supported') {
            # Role can't be assigned. Roll back the group only if we created it this run.
            if ($status.Action -eq 'Created group' -and $status.GroupId) {
                try { Remove-MgGroup -GroupId $status.GroupId -ErrorAction Stop; $rolledBack = ' (group removed)' }
                catch { $rolledBack = ' (group left in place - manual cleanup needed)' }
            } else { $rolledBack = '' }
            $status.Action = "Skipped: role not assignable via PIM$rolledBack"
            Write-Host ("  [{0}] skipped - role not assignable" -f $role.DisplayName) -ForegroundColor DarkGray
        } else {
            $status.Action = "ERROR: $msg"
            Write-Warning "[$($role.DisplayName)] $msg"
        }
    }
    $results.Add([pscustomobject]$status)
}

# --- Report ------------------------------------------------------------------
$results | Format-Table -AutoSize
Write-Host "`nDone. Add members to the SG_PIM_* groups to grant them PIM-eligible access." -ForegroundColor Green
